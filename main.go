package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
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
//	               server assigns ID/timestamp and broadcasts it to everyone
//	"edit"       - both directions: client asks to edit an existing message by ID;
//	               server checks the requester is the original author, then broadcasts it
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
	maxHistory     = 200                 // oldest messages are dropped beyond this
	sendBufferSize = 16
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

// Hub owns all shared state: connected clients and message history.
type Hub struct {
	mu      sync.Mutex
	clients map[*Client]bool
	history []Message
	nextID  int64
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // allow LAN/public clients
}

func newHub() *Hub {
	return &Hub{clients: make(map[*Client]bool)}
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

// snapshot returns a copy of the current history, safe to hand to a new client.
func (h *Hub) snapshot() []Message {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Message, len(h.history))
	copy(out, h.history)
	return out
}

// addMessage assigns an ID/timestamp, appends to history (trimmed to
// maxHistory), and returns the stored copy.
func (h *Hub) addMessage(username, text string) Message {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nextID++
	msg := Message{
		Type:      "message",
		ID:        h.nextID,
		Username:  username,
		Text:      text,
		Timestamp: time.Now().Unix(),
	}
	h.history = append(h.history, msg)
	if len(h.history) > maxHistory {
		h.history = h.history[len(h.history)-maxHistory:]
	}
	return msg
}

// applyEdit updates an existing message's text, but only if username
// matches the message's original author. Returns the updated message and
// whether the edit was allowed.
func (h *Hub) applyEdit(id int64, username, text string) (Message, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.history {
		if h.history[i].ID == id {
			if h.history[i].Username != username {
				return Message{}, false
			}
			h.history[i].Text = text
			h.history[i].Timestamp = time.Now().Unix()
			return h.history[i], true
		}
	}
	return Message{}, false
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
			msg := hub.addMessage(c.username, in.Text)
			hub.broadcast(msg)

		case "edit":
			if in.Text == "" {
				continue
			}
			updated, ok := hub.applyEdit(in.ID, c.username, in.Text)
			if !ok {
				continue // no such message, or requester isn't the author - ignore
			}
			updated.Type = "edit"
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
	hub := newHub()

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
