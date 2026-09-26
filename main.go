package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Message is the structure sent between server and clients.
type Message struct {
	Username string `json:"username"`
	Text     string `json:"text"`
}

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10 // must be less than pongWait
	broadcastQueue = 100
)

// Hub keeps track of all connected clients and broadcasts messages.
type Hub struct {
	mu        sync.Mutex
	clients   map[*websocket.Conn]bool
	broadcast chan Message
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // allow LAN clients
}

func newHub() *Hub {
	return &Hub{
		clients:   make(map[*websocket.Conn]bool),
		broadcast: make(chan Message, broadcastQueue),
	}
}

func (h *Hub) addClient(ws *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[ws] = true
}

func (h *Hub) removeClient(ws *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.clients, ws)
}

// run listens for new messages and sends them to every connected client.
// Each write gets a deadline so one slow/dead client can't stall the
// whole broadcast loop while the lock is held.
func (h *Hub) run() {
	for msg := range h.broadcast {
		h.mu.Lock()
		for client := range h.clients {
			client.SetWriteDeadline(time.Now().Add(writeWait))
			if err := client.WriteJSON(msg); err != nil {
				log.Printf("write error, dropping client %s: %v", client.RemoteAddr(), err)
				client.Close()
				delete(h.clients, client)
			}
		}
		h.mu.Unlock()
	}
}

// writePump sends periodic pings so dead connections (e.g. a client that
// vanished without closing cleanly) get detected instead of hanging forever.
func writePump(ws *websocket.Conn) {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()
	for range ticker.C {
		ws.SetWriteDeadline(time.Now().Add(writeWait))
		if err := ws.WriteMessage(websocket.PingMessage, nil); err != nil {
			return
		}
	}
}

// handleConnections upgrades HTTP to WebSocket and reads incoming messages.
func handleConnections(hub *Hub, w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade error:", err)
		return
	}
	defer ws.Close()

	ws.SetReadDeadline(time.Now().Add(pongWait))
	ws.SetPongHandler(func(string) error {
		ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	hub.addClient(ws)
	log.Printf("Client connected: %s", ws.RemoteAddr())

	go writePump(ws)

	defer func() {
		hub.removeClient(ws)
		log.Printf("Client disconnected: %s", ws.RemoteAddr())
	}()

	for {
		var msg Message
		if err := ws.ReadJSON(&msg); err != nil {
			break
		}
		hub.broadcast <- msg
	}
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
	go hub.run()

	// Static route — serves files from the ./static folder at "/"
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
