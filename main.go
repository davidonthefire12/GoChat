package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

// ReplyPreview is the small quoted snippet shown above a reply. The server
// builds it from the database (never from client input) so it can't be spoofed.
// Deleted is true once the original message no longer exists.
type ReplyPreview struct {
	ID       int64  `json:"id"`
	Username string `json:"username,omitempty"`
	Text     string `json:"text,omitempty"`
	Deleted  bool   `json:"deleted,omitempty"`
}

// Message is exchanged between server and clients over the websocket.
// Authentication happens over HTTP (/api/login sets an HttpOnly session
// cookie); the websocket upgrade is authorised by that cookie, so no
// credentials ever travel over the socket. Type distinguishes payloads:
//
//	"joined"  - server -> client only, first frame after the upgrade, with
//	            the canonical (originally-registered) username casing
//	"history" - server -> client only, sent once right after "joined"
//	"message" - both directions: client sends text (+ optional reply_to_id);
//	            server stores it, assigns ID/timestamp/reply preview, broadcasts it
//	"edit"    - both directions: author-only edit by ID, persisted then broadcast
//	"delete"  - both directions: author-only delete by ID, then broadcast {type:"delete", id}
type Message struct {
	Type      string        `json:"type"`
	ID        int64         `json:"id,omitempty"`
	Username  string        `json:"username,omitempty"`
	Text      string        `json:"text,omitempty"`
	Timestamp int64         `json:"timestamp,omitempty"`
	ReplyToID int64         `json:"reply_to_id,omitempty"` // client -> server: which message is being replied to
	Reply     *ReplyPreview `json:"reply,omitempty"`       // server -> client: resolved preview of that message
	History   []Message     `json:"history,omitempty"`
	Members   []Member      `json:"members,omitempty"` // "presence" frames
}

// Member is one registered user and whether they currently have a live socket.
type Member struct {
	Username string `json:"username"`
	Online   bool   `json:"online"`
}

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10 // must be less than pongWait
	maxHistory     = 200                 // how many recent messages are cached/synced to new clients
	sendBufferSize = 16
	dbTimeout      = 5 * time.Second
	minPasswordLen = 4
)

const (
	sessionCookie   = "chat_session"
	sessionTTL      = 30 * 24 * time.Hour
	replyPreviewLen = 120
)

var (
	errNoSession    = errors.New("no valid session")
	errUserNotFound = errors.New("user not found")
)

// Client represents one connected websocket connection.
// Every write to conn goes through the send channel and is handled by a
// single writePump goroutine per client, so broadcasts, pings, and the
// initial history push never race on the same connection.
//
// Multiple Clients can share the same username at once (e.g. the same
// person logged in from phone and laptop) - that's safe now because the
// username is password-protected, not just claimed by whoever types it first.
type Client struct {
	conn      *websocket.Conn
	send      chan Message
	username  string
	tokenHash string // which login session this socket belongs to (for logout)
}

// Hub owns all shared state: connected clients and an in-memory cache of
// the most recent messages. Postgres (Supabase) is the durable source of
// truth for both messages and user accounts - the cache just makes syncing
// a newly joined client fast.
type Hub struct {
	mu      sync.Mutex
	clients map[*Client]bool
	history []Message
	db      *sql.DB
}

var upgrader = websocket.Upgrader{
	// Cookie-authenticated sockets must only be opened by our own pages
	// (blocks cross-site WebSocket hijacking). Non-browser clients send no Origin.
	CheckOrigin: sameOrigin,
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
		`SELECT m.id, m.username, m.text, m.created_at, m.reply_to, r.username, r.text
		 FROM messages m LEFT JOIN messages r ON r.id = m.reply_to
		 ORDER BY m.id DESC LIMIT $1`,
		maxHistory,
	)
	if err != nil {
		return fmt.Errorf("query history: %w", err)
	}
	defer rows.Close()

	var loaded []Message
	for rows.Next() {
		var m Message
		var replyID sql.NullInt64
		var ru, rt sql.NullString
		if err := rows.Scan(&m.ID, &m.Username, &m.Text, &m.Timestamp, &replyID, &ru, &rt); err != nil {
			return fmt.Errorf("scan history row: %w", err)
		}
		m.Type = "message"
		if replyID.Valid {
			m.ReplyToID = replyID.Int64
			if ru.Valid {
				m.Reply = &ReplyPreview{ID: replyID.Int64, Username: ru.String, Text: previewOf(rt.String)}
			} else {
				m.Reply = &ReplyPreview{ID: replyID.Int64, Deleted: true} // original was deleted
			}
		}
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

// authenticate checks a username/password pair against the users table.
// Accounts are created by an administrator (see the "adduser" command in
// main), never by logging in. It returns errUserNotFound for an unknown
// username, ok=false for a wrong password, and the canonical (originally
// registered) username casing on success.
func (h *Hub) authenticate(ctx context.Context, username, password string) (canonical string, ok bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	var storedUsername, hash string
	err = h.db.QueryRowContext(ctx,
		`SELECT username, password_hash FROM users WHERE username_lower = $1`,
		strings.ToLower(username),
	).Scan(&storedUsername, &hash)
	if err == sql.ErrNoRows {
		return "", false, errUserNotFound
	}
	if err != nil {
		return "", false, fmt.Errorf("lookup user: %w", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return "", false, nil
	}
	return storedUsername, true, nil
}

// addUser creates an account. Used by the "adduser" command-line mode.
func addUser(db *sql.DB, username, password string) error {
	username = strings.TrimSpace(username)
	if username == "" || len(username) > 30 {
		return fmt.Errorf("username must be 1-30 characters")
	}
	if len(password) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	res, err := db.ExecContext(ctx,
		`INSERT INTO users (username_lower, username, password_hash, created_at)
		 VALUES ($1, $2, $3, $4) ON CONFLICT (username_lower) DO NOTHING`,
		strings.ToLower(username), username, string(hash), time.Now().Unix())
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("user %q already exists", username)
	}
	return nil
}

// broadcastPresence sends every client the full member list with online flags.
// Called whenever someone connects or disconnects.
func (h *Hub) broadcastPresence() {
	h.mu.Lock()
	online := make(map[string]bool, len(h.clients))
	for c := range h.clients {
		online[strings.ToLower(c.username)] = true
	}
	h.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	rows, err := h.db.QueryContext(ctx, `SELECT username FROM users ORDER BY username_lower`)
	if err != nil {
		log.Printf("presence query failed: %v", err)
		return
	}
	defer rows.Close()

	var members []Member
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			log.Printf("presence scan failed: %v", err)
			return
		}
		members = append(members, Member{Username: u, Online: online[strings.ToLower(u)]})
	}
	if err := rows.Err(); err != nil {
		log.Printf("presence rows failed: %v", err)
		return
	}
	h.broadcast(Message{Type: "presence", Members: members})
}

// previewOf truncates quoted text for the reply snippet.
func previewOf(text string) string {
	r := []rune(text)
	if len(r) > replyPreviewLen {
		return string(r[:replyPreviewLen]) + "…"
	}
	return text
}

// setReplyPreviewLocked refreshes the cached preview on every message that
// replies to id. Callers must hold h.mu. It swaps in a new pointer instead of
// mutating the old one, because earlier snapshots may still be marshalling it.
func (h *Hub) setReplyPreviewLocked(id int64, p ReplyPreview) {
	for i := range h.history {
		if h.history[i].ReplyToID == id {
			cp := p
			h.history[i].Reply = &cp
		}
	}
}

// ensureSchema applies the idempotent migrations this version needs:
// a reply_to column on messages and a sessions table.
func (h *Hub) ensureSchema(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	for _, stmt := range []string{
		`ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to BIGINT`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token_hash TEXT PRIMARY KEY,
			username   TEXT NOT NULL,
			created_at BIGINT NOT NULL,
			expires_at BIGINT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions (expires_at)`,
	} {
		if _, err := h.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

// hashToken returns the SHA-256 of a session token. Only the hash is stored,
// so a database leak doesn't hand out usable sessions.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// createSession issues a new random 256-bit token and stores its hash.
func (h *Hub) createSession(ctx context.Context, username string) (string, time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", time.Time{}, fmt.Errorf("generate token: %w", err)
	}
	token := hex.EncodeToString(buf)
	now := time.Now()
	expires := now.Add(sessionTTL)

	if _, err := h.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= $1`, now.Unix()); err != nil {
		log.Printf("expired session cleanup failed: %v", err) // non-fatal
	}
	if _, err := h.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, username, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
		hashToken(token), username, now.Unix(), expires.Unix(),
	); err != nil {
		return "", time.Time{}, fmt.Errorf("store session: %w", err)
	}
	return token, expires, nil
}

// sessionFromRequest resolves the session cookie to a username. It returns
// errNoSession when the cookie is missing, unknown or expired, and any other
// error for infrastructure failures (so a DB blip isn't mistaken for an expired login).
func (h *Hub) sessionFromRequest(r *http.Request) (username, tokenHash string, err error) {
	c, cerr := r.Cookie(sessionCookie)
	if cerr != nil || c.Value == "" {
		return "", "", errNoSession
	}
	tokenHash = hashToken(c.Value)

	ctx, cancel := context.WithTimeout(r.Context(), dbTimeout)
	defer cancel()
	qerr := h.db.QueryRowContext(ctx,
		`SELECT username FROM sessions WHERE token_hash = $1 AND expires_at > $2`,
		tokenHash, time.Now().Unix(),
	).Scan(&username)
	if qerr == sql.ErrNoRows {
		return "", "", errNoSession
	}
	if qerr != nil {
		return "", "", fmt.Errorf("lookup session: %w", qerr)
	}
	return username, tokenHash, nil
}

func (h *Hub) deleteSession(ctx context.Context, tokenHash string) error {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	_, err := h.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

// kickSession closes every live socket that belongs to a logged-out session.
func (h *Hub) kickSession(tokenHash string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		if c.tokenHash == tokenHash {
			c.conn.Close() // readPump unwinds and calls removeClient
		}
	}
}

// addClient adds an already-authenticated client to the active set.
// No uniqueness check here - a verified username can have several
// simultaneous connections (multiple devices, same identity).
func (h *Hub) addClient(c *Client) {
	h.mu.Lock()
	h.clients[c] = true
	h.mu.Unlock()
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
func (h *Hub) addMessage(ctx context.Context, username, text string, replyToID int64) (Message, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	// Resolve the quoted message server-side. If it no longer exists the
	// text is still sent, just as a plain (non-reply) message.
	var preview *ReplyPreview
	var replyArg interface{}
	if replyToID > 0 {
		var ru, rt string
		err := h.db.QueryRowContext(ctx, `SELECT username, text FROM messages WHERE id = $1`, replyToID).Scan(&ru, &rt)
		switch {
		case err == nil:
			preview = &ReplyPreview{ID: replyToID, Username: ru, Text: previewOf(rt)}
			replyArg = replyToID
		case err != sql.ErrNoRows:
			return Message{}, fmt.Errorf("lookup reply target: %w", err)
		}
	}

	ts := time.Now().Unix()
	var id int64
	err := h.db.QueryRowContext(ctx,
		`INSERT INTO messages (username, text, created_at, reply_to) VALUES ($1, $2, $3, $4) RETURNING id`,
		username, text, ts, replyArg,
	).Scan(&id)
	if err != nil {
		return Message{}, fmt.Errorf("insert message: %w", err)
	}

	msg := Message{Type: "message", ID: id, Username: username, Text: text, Timestamp: ts, Reply: preview}
	if preview != nil {
		msg.ReplyToID = preview.ID
	}

	h.mu.Lock()
	h.history = append(h.history, msg)
	if len(h.history) > maxHistory {
		h.history = h.history[len(h.history)-maxHistory:]
	}
	h.mu.Unlock()

	return msg, nil
}

// applyEdit updates an existing message's text in Postgres, but only if
// username matches the message's original author. Comparison is
// case-insensitive defensively, though canonical usernames from
// authenticate() should already be consistent across sessions/devices.
// Enforced in the SQL WHERE clause itself, so it's race-safe against
// concurrent edits.
func (h *Hub) applyEdit(ctx context.Context, id int64, username, text string) (Message, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	ts := time.Now().Unix()
	res, err := h.db.ExecContext(ctx,
		`UPDATE messages SET text = $1, edited_at = $2 WHERE id = $3 AND lower(username) = lower($4)`,
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
	h.setReplyPreviewLocked(id, ReplyPreview{ID: id, Username: username, Text: previewOf(text)})
	h.mu.Unlock()

	return updated, true, nil
}

// deleteMessage removes a message from Postgres, but only if username
// matches the original author (same case-insensitive check as edits,
// enforced in SQL). Returns whether a row was actually deleted.
func (h *Hub) deleteMessage(ctx context.Context, id int64, username string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()

	res, err := h.db.ExecContext(ctx,
		`DELETE FROM messages WHERE id = $1 AND lower(username) = lower($2)`,
		id, username,
	)
	if err != nil {
		return false, fmt.Errorf("delete message: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return false, nil // no such message, or requester isn't the author
	}

	h.mu.Lock()
	for i := range h.history {
		if h.history[i].ID == id {
			h.history = append(h.history[:i], h.history[i+1:]...)
			break
		}
	}
	h.setReplyPreviewLocked(id, ReplyPreview{ID: id, Deleted: true})
	h.mu.Unlock()

	return true, nil
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
		go hub.broadcastPresence()
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
			msg, err := hub.addMessage(context.Background(), c.username, in.Text, in.ReplyToID)
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

		case "delete":
			ok, err := hub.deleteMessage(context.Background(), in.ID, c.username)
			if err != nil {
				log.Printf("failed to delete message for %s: %v", c.username, err)
				continue
			}
			if !ok {
				continue // no such message, or requester isn't the author - ignore
			}
			hub.broadcast(Message{Type: "delete", ID: in.ID})

		default:
			// unknown/legacy message type, ignore
		}
	}
}

// sameOrigin reports whether a request's Origin header (if any) matches the
// host it was sent to. Used for the websocket handshake and state-changing POSTs.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // non-browser client
	}
	u, err := url.Parse(origin)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func isSecure(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// The session cookie is HttpOnly (invisible to page JavaScript, so XSS can't
// steal it), SameSite=Lax (not sent on cross-site requests) and Secure over HTTPS.
func setSessionCookie(w http.ResponseWriter, r *http.Request, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/",
		Expires: expires, MaxAge: int(time.Until(expires).Seconds()),
		HttpOnly: true, Secure: isSecure(r), SameSite: http.SameSiteLaxMode,
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: isSecure(r), SameSite: http.SameSiteLaxMode,
	})
}

// requirePost rejects anything but a same-origin POST.
func requirePost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		apiError(w, http.StatusMethodNotAllowed, "Method not allowed.")
		return false
	}
	if !sameOrigin(r) {
		apiError(w, http.StatusForbidden, "Forbidden.")
		return false
	}
	return true
}

// handleLogin: POST {username, password}. Existing users only: unknown names
// are rejected, never registered. Success starts a persistent cookie session.
func handleLogin(hub *Hub, w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	name := strings.TrimSpace(req.Username)
	if name == "" {
		apiError(w, http.StatusBadRequest, "Please enter a name.")
		return
	}
	if len(name) > 30 {
		name = name[:30]
	}
	if len(req.Password) < minPasswordLen {
		apiError(w, http.StatusBadRequest, fmt.Sprintf("Password must be at least %d characters.", minPasswordLen))
		return
	}

	canonical, ok, err := hub.authenticate(r.Context(), name, req.Password)
	if errors.Is(err, errUserNotFound) {
		apiError(w, http.StatusUnauthorized, "User not found. Please contact the administrator.")
		return
	}
	if err != nil {
		log.Printf("auth error for %q: %v", name, err)
		apiError(w, http.StatusInternalServerError, "Server error, please try again.")
		return
	}
	if !ok {
		apiError(w, http.StatusUnauthorized, "Incorrect password for that username.")
		return
	}

	token, expires, err := hub.createSession(r.Context(), canonical)
	if err != nil {
		log.Printf("session error for %q: %v", canonical, err)
		apiError(w, http.StatusInternalServerError, "Server error, please try again.")
		return
	}
	setSessionCookie(w, r, token, expires)
	writeJSON(w, http.StatusOK, map[string]string{"username": canonical})
}

// handleLogout: POST. Deletes the session server-side, closes its live
// sockets, and clears the cookie.
func handleLogout(hub *Hub, w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		hash := hashToken(c.Value)
		if err := hub.deleteSession(r.Context(), hash); err != nil {
			log.Printf("logout failed: %v", err)
			apiError(w, http.StatusInternalServerError, "Could not log out, please try again.")
			return
		}
		hub.kickSession(hash)
	}
	clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleSession: GET. 200 {username} if the cookie is a live session, 401 otherwise.
func handleSession(hub *Hub, w http.ResponseWriter, r *http.Request) {
	username, _, err := hub.sessionFromRequest(r)
	switch {
	case errors.Is(err, errNoSession):
		clearSessionCookie(w, r) // drop a stale cookie
		apiError(w, http.StatusUnauthorized, "Not logged in.")
	case err != nil:
		log.Printf("session check failed: %v", err)
		apiError(w, http.StatusServiceUnavailable, "Server error, please try again.")
	default:
		writeJSON(w, http.StatusOK, map[string]string{"username": username})
	}
}

// handleConnections authenticates the session cookie *before* upgrading, so
// unauthenticated requests never get a socket, then starts the pumps.
func handleConnections(hub *Hub, w http.ResponseWriter, r *http.Request) {
	username, tokenHash, err := hub.sessionFromRequest(r)
	if err != nil {
		if errors.Is(err, errNoSession) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		} else {
			log.Printf("ws session check failed: %v", err)
			http.Error(w, "server error", http.StatusServiceUnavailable)
		}
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade error:", err)
		return
	}

	client := &Client{
		conn:      ws,
		send:      make(chan Message, sendBufferSize),
		username:  username,
		tokenHash: tokenHash,
	}
	hub.addClient(client)
	log.Printf("Client connected: %s (%s)", ws.RemoteAddr(), client.username)

	go client.writePump()

	// "joined" first so the client knows its own name before rendering history.
	client.send <- Message{Type: "joined", Username: client.username}
	client.send <- Message{Type: "history", History: hub.snapshot()}

	go hub.broadcastPresence()
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
	// Loads variables from a local .env file, if one exists, into the
	// process environment. Silently does nothing if the file is missing -
	// that's the normal case on Render, which injects env vars directly.
	_ = godotenv.Load()

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

	// Account administration: `go run . adduser <username> <password>`
	if len(os.Args) == 4 && os.Args[1] == "adduser" {
		if err := addUser(db, os.Args[2], os.Args[3]); err != nil {
			log.Fatal("adduser: ", err)
		}
		fmt.Println("Created user:", os.Args[2])
		return
	}

	hub := newHub(db)
	if err := hub.ensureSchema(context.Background()); err != nil {
		log.Fatal("failed to migrate schema: ", err)
	}
	if err := hub.loadHistory(context.Background()); err != nil {
		log.Fatal("failed to load chat history: ", err)
	}

	// Static route - serves files from the ./static folder at "/"
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	// Auth routes
	http.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) { handleLogin(hub, w, r) })
	http.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) { handleLogout(hub, w, r) })
	http.HandleFunc("/api/session", func(w http.ResponseWriter, r *http.Request) { handleSession(hub, w, r) })

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
