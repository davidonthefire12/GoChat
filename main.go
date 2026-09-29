package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

// Message is exchanged between server and clients over the websocket.
// Type distinguishes the different kinds of payload:
//
//	"join"       - client -> server, first message on connect, announces the username
//	"joined"     - server -> client only, confirms the join succeeded with the final username
//	"join_error" - server -> client only, sent instead of "joined" when the name is taken/invalid;
//	               the connection stays open so the client can retry with a different name
//	"history"    - server -> client only, sent once right after a successful join
//	"message"    - both directions: client sends a new message with no ID;
//	               server stores it in Postgres, assigns ID/timestamp, and broadcasts it
//	"edit"       - both directions: client asks to edit an existing message by ID;
//	               server checks the requester is the original author, persists it, then broadcasts it
type Message struct {
	Type      string    `json:"type"`
	ID        int64     `json:"id,omitempty"`
	Username  string    `json:"username,omitempty"`
	Text      string    `json:"text,omitempty"`
	Timestamp int64     `json:"ts,omitempty"`
	History   []Message `json:"history,omitempty"`
}

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10 // must be less than pongWait
	maxHistory     = 200                 // how many recent messages are cached/synced to new clients
	sendBufferSize = 16
	dbTimeout      = 5 * time.Second
)

// Client represents one connected websocket connection.
// Every write to conn goes through the send channel and is handled by a
// single writePump goroutine per client, so broadcasts, pings, and the
// initial history push never race on the same connection.
type Client struct {
	conn     *websocket.Conn
	send     chan Message
	username string
}

// Hub owns all shared state: connected clients and an in-memory cache of
// the most recent messages. Postgres (Supabase) is the durable source of
// truth - the cache just makes syncing a newly joined client fast and lets
// the app keep working (in a degraded, non-persistent way) if the database
// is briefly unreachable for a write.
type Hub struct {
	mu      sync.Mutex
	clients map[*Client]bool
	history []Message
	db      *sql.DB
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // allow LAN/public clients
}

func newHub(db *sql.DB) *Hub {
	return &Hub{clients: make(map[*Client]bool), db: db}
}

// loadHistory populates the in-memory cache from Postgres. Call this once
// at startup before accepting connections.
func (h *Hub) loadHistory(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	rows, err := h.db.QueryContext(ctx,
		`SELECT id, username, text, created_at FROM messages ORDER BY id DESC LIMIT $1`,
		maxHistory,
	)
	if err != nil {
		return fmt.Errorf("query history: %w", err)
	}
	defer rows.Close()

	var loaded []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.Username, &m.Text, &m.Timestamp); err != nil {
			return fmt.Errorf("scan history row: %w", err)
		}
		m.Type = "message"
		loaded = append(loaded, m)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate history rows: %w", err)
	}

	// Rows came back newest-first; reverse to chronological order.
	for i, j := 0, len(loaded)-1; i < j; i, j = i+1, j-1 {
		loaded[i], loaded[j] = loaded[j], loaded[i]
	}

	h.mu.Lock()
	h.history = loaded
	h.mu.Unlock()
	return nil
}

// tryAddClient reserves c's username and adds it to the client set, but
// only if no other currently-connected client already holds that name
// (case-insensitive). The check and the insert happen under one lock so
// two simultaneous join attempts for the same name can't both succeed.
func (h *Hub) tryAddClient(c *Client) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for existing := range h.clients {
		if strings.EqualFold(existing.username, c.username) {
			return false
		}
	}
	h.clients[c] = true
	return true
}

// removeClient deletes c from the client set and closes its send channel,
// but only the first time it's called for a given client - this makes it
// safe to call from both the normal disconnect path and the "buffer full,
// drop this client" path without ever double-closing the channel.
func (h *Hub) removeClient(c *Client) {
	h.mu.Lock()
	_, present := h.clients[c]
	if present {
		delete(h.clients, c)
	}
	h.mu.Unlock()
	if present {
		close(c.send)
	}
}

// snapshot returns a copy of the current history cache, safe to hand to a new client.
func (h *Hub) snapshot() []Message {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Message, len(h.history))
	copy(out, h.history)
	return out
}

// addMessage persists a new message to Postgres (which assigns the ID),
// then mirrors it into the in-memory cache. The message is only broadcast
// by the caller if this succeeds, so nothing reaches other clients without
// being durably saved first.
func (h *Hub) addMessage(ctx context.Context, username, text string) (Message, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	ts := time.Now().Unix()
	var id int64
	err := h.db.QueryRowContext(ctx,
		`INSERT INTO messages (username, text, created_at) VALUES ($1, $2, $3) RETURNING id`,
		username, text, ts,
	).Scan(&id)
	if err != nil {
		return Message{}, fmt.Errorf("insert message: %w", err)
	}

	msg := Message{Type: "message", ID: id, Username: username, Text: text, Timestamp: ts}

	h.mu.Lock()
	h.history = append(h.history, msg)
	if len(h.history) > maxHistory {
		h.history = h.history[len(h.history)-maxHistory:]
	}
	h.mu.Unlock()

	return msg, nil
}

// applyEdit updates an existing message's text in Postgres, but only if
// username matches the message's original author (enforced in the SQL
// WHERE clause itself, so it's race-safe against concurrent edits).
// Returns the updated message and whether the edit was allowed.
func (h *Hub) applyEdit(ctx context.Context, id int64, username, text string) (Message, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	ts := time.Now().Unix()
	res, err := h.db.ExecContext(ctx,
		`UPDATE messages SET text = $1, edited_at = $2 WHERE id = $3 AND username = $4`,
		text, ts, id, username,
	)
	if err != nil {
		return Message{}, false, fmt.Errorf("update message: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Message{}, false, fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return Message{}, false, nil // no such message, or requester isn't the author
	}

	updated := Message{Type: "edit", ID: id, Username: username, Text: text, Timestamp: ts}

	h.mu.Lock()
	for i := range h.history {
		if h.history[i].ID == id {
			h.history[i].Text = text
			h.history[i].Timestamp = ts
			break
		}
	}
	h.mu.Unlock()

	return updated, true, nil
}

// broadcast queues msg for every connected client. A client whose buffer
// is already full is treated as stuck: it's dropped and its connection is
// closed, which unwinds cleanly through that client's own readPump/removeClient.
func (h *Hub) broadcast(msg Message) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		select {
		case c.send <- msg:
		default:
			log.Printf("client %s send buffer full, dropping", c.conn.RemoteAddr())
			delete(h.clients, c)
			c.conn.Close()
		}
	}
}

// writePump owns every write to the underlying connection: broadcast
// messages, the initial history push, and periodic pings. Nothing else
// should ever call c.conn.WriteJSON/WriteMessage directly.
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case msg, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteJSON(msg); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// readPump reads incoming messages from this client and acts on them.
func (c *Client) readPump(hub *Hub) {
	defer func() {
		hub.removeClient(c)
		log.Printf("Client disconnected: %s (%s)", c.conn.RemoteAddr(), c.username)
	}()

	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		var in Message
		if err := c.conn.ReadJSON(&in); err != nil {
			break
		}

		switch in.Type {
		case "message":
			if in.Text == "" {
				continue
			}
			msg, err := hub.addMessage(context.Background(), c.username, in.Text)
			if err != nil {
				log.Printf("failed to store message from %s: %v", c.username, err)
				continue // don't broadcast anything that wasn't actually saved
			}
			hub.broadcast(msg)

		case "edit":
			if in.Text == "" {
				continue
			}
			updated, ok, err := hub.applyEdit(context.Background(), in.ID, c.username, in.Text)
			if err != nil {
				log.Printf("failed to apply edit from %s: %v", c.username, err)
				continue
			}
			if !ok {
				continue // no such message, or requester isn't the author - ignore
			}
			hub.broadcast(updated)

		default:
			// unknown/legacy message type, ignore
		}
	}
}

// handleConnections upgrades HTTP to WebSocket, then negotiates a unique
// username via repeated "join" attempts before starting the read/write pumps.
func handleConnections(hub *Hub, w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade error:", err)
		return
	}

	var client *Client
	for {
		var join Message
		if err := ws.ReadJSON(&join); err != nil {
			ws.Close()
			return
		}
		if join.Type != "join" {
			continue // ignore anything before a valid join attempt
		}

		name := strings.TrimSpace(join.Username)
		if name == "" {
			if err := ws.WriteJSON(Message{Type: "join_error", Text: "Please enter a name."}); err != nil {
				ws.Close()
				return
			}
			continue
		}
		if len(name) > 30 {
			name = name[:30]
		}

		candidate := &Client{
			conn:     ws,
			send:     make(chan Message, sendBufferSize),
			username: name,
		}

		if !hub.tryAddClient(candidate) {
			if err := ws.WriteJSON(Message{Type: "join_error", Text: "That name is already taken. Choose another."}); err != nil {
				ws.Close()
				return
			}
			continue
		}

		client = candidate
		break
	}

	log.Printf("Client connected: %s (%s)", ws.RemoteAddr(), client.username)

	go client.writePump()

	// Push history, then confirm the join, both via this client's own send
	// channel so they're serialized with everything else written to this
	// connection (writePump is now the only goroutine writing to ws).
	client.send <- Message{Type: "history", History: hub.snapshot()}
	client.send <- Message{Type: "joined", Username: client.username}

	client.readPump(hub)
}

// getLocalIP automatically detects this PC's LAN IP address.
func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "localhost"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL is not set - point it at your Supabase Postgres connection string")
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		log.Fatal("failed to open database: ", err)
	}
	defer db.Close()

	// Keep the pool small and bounded - Supabase's pooler has a connection
	// limit shared across everything using the project, and this app only
	// ever needs a handful of connections at a time.
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	pingCtx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	if err := db.PingContext(pingCtx); err != nil {
		cancel()
		log.Fatal("failed to connect to database: ", err)
	}
	cancel()

	hub := newHub(db)
	if err := hub.loadHistory(context.Background()); err != nil {
		log.Fatal("failed to load chat history: ", err)
	}

	// Static route - serves files from the ./static folder at "/"
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	// WebSocket route
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		handleConnections(hub, w, r)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	addr := ":" + port
	ip := getLocalIP()

	fmt.Println("========================================")
	fmt.Println("  Chat server running!")
	fmt.Printf("  On this PC:      http://localhost%s\n", addr)
	fmt.Printf("  Share with LAN:  http://%s%s\n", ip, addr)
	fmt.Println("========================================")

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
