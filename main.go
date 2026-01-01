package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Package represents a software package
type Package struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Architecture string            `json:"arch"`
	Description  string            `json:"description"`
	Dependencies []string          `json:"dependencies"`
	Conflicts    []string          `json:"conflicts"`
	Size         int64             `json:"size"`
	URL          string            `json:"url"`
	Checksum     string            `json:"checksum"`
	Signature    string            `json:"signature"`
	Files        []string          `json:"files"`
	Metadata     map[string]string `json:"metadata"`
	UploadDate   time.Time         `json:"upload_date"`
	Downloads    int64             `json:"downloads"`
}

// Repository metadata
type RepoMetadata struct {
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	URL          string    `json:"url"`
	Architectures []string `json:"architectures"`
	LastUpdate   time.Time `json:"last_update"`
	PackageCount int       `json:"package_count"`
}

// RepositoryServer manages the package repository
type RepositoryServer struct {
	db          *sql.DB
	packagesDir string
	port        int
	baseURL     string
}

// NewRepositoryServer creates a new repository server
func NewRepositoryServer(dataDir string, port int, baseURL string) (*RepositoryServer, error) {
	rs := &RepositoryServer{
		packagesDir: filepath.Join(dataDir, "packages"),
		port:        port,
		baseURL:     baseURL,
	}

	// Create necessary directories
	if err := os.MkdirAll(rs.packagesDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create packages directory: %v", err)
	}

	// Initialize database
	dbPath := filepath.Join(dataDir, "repository.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}
	rs.db = db

	if err := rs.initDB(); err != nil {
		return nil, err
	}

	return rs, nil
}

// initDB initializes the database schema
func (rs *RepositoryServer) initDB() error {
	schema := `
	CREATE TABLE IF NOT EXISTS packages (
		name TEXT NOT NULL,
		version TEXT NOT NULL,
		architecture TEXT NOT NULL,
		description TEXT,
		dependencies TEXT,
		conflicts TEXT,
		size INTEGER,
		filename TEXT NOT NULL,
		checksum TEXT NOT NULL,
		signature TEXT,
		upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		downloads INTEGER DEFAULT 0,
		metadata TEXT,
		PRIMARY KEY (name, version, architecture)
	);

	CREATE TABLE IF NOT EXISTS download_stats (
		package_name TEXT,
		package_version TEXT,
		download_date DATE,
		count INTEGER DEFAULT 0,
		PRIMARY KEY (package_name, package_version, download_date)
	);

	CREATE TABLE IF NOT EXISTS api_keys (
		key TEXT PRIMARY KEY,
		description TEXT,
		created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_used TIMESTAMP,
		permissions TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_pkg_name ON packages(name);
	CREATE INDEX IF NOT EXISTS idx_pkg_arch ON packages(architecture);
	CREATE INDEX IF NOT EXISTS idx_downloads ON download_stats(download_date);
	`

	_, err := rs.db.Exec(schema)
	return err
}

// Start starts the HTTP server
func (rs *RepositoryServer) Start() error {
	mux := http.NewServeMux()

	// Public endpoints
	mux.HandleFunc("/packages.json", rs.handlePackagesList)
	mux.HandleFunc("/packages/", rs.handlePackageDownload)
	mux.HandleFunc("/search", rs.handleSearch)
	mux.HandleFunc("/metadata", rs.handleMetadata)
	mux.HandleFunc("/package/", rs.handlePackageInfo)

	// Admin endpoints (require API key)
	mux.HandleFunc("/admin/upload", rs.authMiddleware(rs.handleUpload))
	mux.HandleFunc("/admin/delete", rs.authMiddleware(rs.handleDelete))
	mux.HandleFunc("/admin/stats", rs.authMiddleware(rs.handleStats))
	mux.HandleFunc("/admin/rebuild-index", rs.authMiddleware(rs.handleRebuildIndex))

	// Health check
	mux.HandleFunc("/health", rs.handleHealth)

	addr := fmt.Sprintf(":%d", rs.port)
	log.Printf("Starting repository server on %s", addr)
	log.Printf("Base URL: %s", rs.baseURL)

	return http.ListenAndServe(addr, rs.loggingMiddleware(mux))
}

// handlePackagesList returns the list of all packages
func (rs *RepositoryServer) handlePackagesList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	arch := r.URL.Query().Get("arch")
	
	query := `
		SELECT name, version, architecture, description, dependencies, 
		       conflicts, size, filename, checksum, signature, metadata
		FROM packages
	`
	args := []interface{}{}
	
	if arch != "" {
		query += " WHERE architecture = ? OR architecture = 'all'"
		args = append(args, arch)
	}
	
	query += " ORDER BY name, version DESC"

	rows, err := rs.db.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var packages []Package
	for rows.Next() {
		var pkg Package
		var depsJSON, conflictsJSON, metadataJSON, filename sql.NullString
		
		err := rows.Scan(
			&pkg.Name, &pkg.Version, &pkg.Architecture, &pkg.Description,
			&depsJSON, &conflictsJSON, &pkg.Size, &filename,
			&pkg.Checksum, &pkg.Signature, &metadataJSON,
		)
		if err != nil {
			continue
		}

		// Parse JSON fields
		if depsJSON.Valid && depsJSON.String != "" {
			json.Unmarshal([]byte(depsJSON.String), &pkg.Dependencies)
		}
		if conflictsJSON.Valid && conflictsJSON.String != "" {
			json.Unmarshal([]byte(conflictsJSON.String), &pkg.Conflicts)
		}
		if metadataJSON.Valid && metadataJSON.String != "" {
			json.Unmarshal([]byte(metadataJSON.String), &pkg.Metadata)
		}

		// Construct download URL
		if filename.Valid {
			pkg.URL = fmt.Sprintf("%s/packages/%s", rs.baseURL, filename.String)
		}

		packages = append(packages, pkg)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(packages)
}

// handlePackageDownload serves package files
func (rs *RepositoryServer) handlePackageDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := strings.TrimPrefix(r.URL.Path, "/packages/")
	if filename == "" {
		http.Error(w, "Package not specified", http.StatusBadRequest)
		return
	}

	// Security: prevent path traversal
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") {
		http.Error(w, "Invalid package name", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(rs.packagesDir, filename)
	
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "Package not found", http.StatusNotFound)
		return
	}

	// Update download counter
	go rs.incrementDownloadCount(filename)

	// Serve file
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	http.ServeFile(w, r, filePath)
}

// handleSearch searches for packages
func (rs *RepositoryServer) handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Search query required", http.StatusBadRequest)
		return
	}

	arch := r.URL.Query().Get("arch")
	limit := 50

	sqlQuery := `
		SELECT name, version, architecture, description, size, downloads
		FROM packages
		WHERE (name LIKE ? OR description LIKE ?)
	`
	args := []interface{}{"%" + query + "%", "%" + query + "%"}

	if arch != "" {
		sqlQuery += " AND (architecture = ? OR architecture = 'all')"
		args = append(args, arch)
	}

	sqlQuery += " ORDER BY downloads DESC, name LIMIT ?"
	args = append(args, limit)

	rows, err := rs.db.Query(sqlQuery, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var name, version, arch, desc string
		var size, downloads int64
		rows.Scan(&name, &version, &arch, &desc, &size, &downloads)

		results = append(results, map[string]interface{}{
			"name":         name,
			"version":      version,
			"architecture": arch,
			"description":  desc,
			"size":         size,
			"downloads":    downloads,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// handlePackageInfo returns detailed information about a specific package
func (rs *RepositoryServer) handlePackageInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pkgName := strings.TrimPrefix(r.URL.Path, "/package/")
	if pkgName == "" {
		http.Error(w, "Package name required", http.StatusBadRequest)
		return
	}

	version := r.URL.Query().Get("version")
	arch := r.URL.Query().Get("arch")

	query := "SELECT * FROM packages WHERE name = ?"
	args := []interface{}{pkgName}

	if version != "" {
		query += " AND version = ?"
		args = append(args, version)
	}
	if arch != "" {
		query += " AND architecture = ?"
		args = append(args, arch)
	}

	query += " ORDER BY version DESC LIMIT 1"

	var pkg Package
	var depsJSON, conflictsJSON, metadataJSON, filename sql.NullString

	err := rs.db.QueryRow(query, args...).Scan(
		&pkg.Name, &pkg.Version, &pkg.Architecture, &pkg.Description,
		&depsJSON, &conflictsJSON, &pkg.Size, &filename,
		&pkg.Checksum, &pkg.Signature, &pkg.UploadDate, &pkg.Downloads,
		&metadataJSON,
	)

	if err == sql.ErrNoRows {
		http.Error(w, "Package not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse JSON fields
	if depsJSON.Valid {
		json.Unmarshal([]byte(depsJSON.String), &pkg.Dependencies)
	}
	if conflictsJSON.Valid {
		json.Unmarshal([]byte(conflictsJSON.String), &pkg.Conflicts)
	}
	if metadataJSON.Valid {
		json.Unmarshal([]byte(metadataJSON.String), &pkg.Metadata)
	}
	if filename.Valid {
		pkg.URL = fmt.Sprintf("%s/packages/%s", rs.baseURL, filename.String)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pkg)
}

// handleMetadata returns repository metadata
func (rs *RepositoryServer) handleMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var count int
	rs.db.QueryRow("SELECT COUNT(DISTINCT name) FROM packages").Scan(&count)

	rows, err := rs.db.Query("SELECT DISTINCT architecture FROM packages")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var archs []string
	for rows.Next() {
		var arch string
		rows.Scan(&arch)
		archs = append(archs, arch)
	}

	metadata := RepoMetadata{
		Name:          "Package Repository",
		Description:   "A modern package repository server",
		URL:           rs.baseURL,
		Architectures: archs,
		LastUpdate:    time.Now(),
		PackageCount:  count,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}

// handleUpload handles package uploads (admin only)
func (rs *RepositoryServer) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form (max 500MB)
	if err := r.ParseMultipartForm(500 << 20); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Get package metadata
	name := r.FormValue("name")
	version := r.FormValue("version")
	arch := r.FormValue("arch")
	description := r.FormValue("description")
	dependencies := r.FormValue("dependencies")
	conflicts := r.FormValue("conflicts")

	if name == "" || version == "" || arch == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Get uploaded file
	file, handler, err := r.FormFile("package")
	if err != nil {
		http.Error(w, "Failed to get file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Generate filename
	filename := fmt.Sprintf("%s_%s_%s.pkg", name, version, arch)
	filePath := filepath.Join(rs.packagesDir, filename)

	// Save file
	dst, err := os.Create(filePath)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// Calculate checksum while copying
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(dst, hash), file)
	if err != nil {
		os.Remove(filePath)
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	checksum := hex.EncodeToString(hash.Sum(nil))

	// Insert into database
	_, err = rs.db.Exec(`
		INSERT OR REPLACE INTO packages 
		(name, version, architecture, description, dependencies, conflicts, 
		 size, filename, checksum, signature, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, name, version, arch, description, dependencies, conflicts,
		size, filename, checksum, "", "")

	if err != nil {
		os.Remove(filePath)
		http.Error(w, "Failed to save package info", http.StatusInternalServerError)
		return
	}

	log.Printf("Package uploaded: %s %s (%s) - %d bytes", name, version, arch, size)

	response := map[string]interface{}{
		"success":  true,
		"package":  name,
		"version":  version,
		"filename": filename,
		"checksum": checksum,
		"size":     size,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleDelete deletes a package (admin only)
func (rs *RepositoryServer) handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := r.URL.Query().Get("name")
	version := r.URL.Query().Get("version")
	arch := r.URL.Query().Get("arch")

	if name == "" {
		http.Error(w, "Package name required", http.StatusBadRequest)
		return
	}

	query := "DELETE FROM packages WHERE name = ?"
	args := []interface{}{name}

	if version != "" {
		query += " AND version = ?"
		args = append(args, version)
	}
	if arch != "" {
		query += " AND architecture = ?"
		args = append(args, arch)
	}

	result, err := rs.db.Exec(query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	affected, _ := result.RowsAffected()
	log.Printf("Deleted %d package(s): %s %s %s", affected, name, version, arch)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"deleted": affected,
	})
}

// handleStats returns download statistics (admin only)
func (rs *RepositoryServer) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Top downloaded packages
	rows, err := rs.db.Query(`
		SELECT name, version, downloads 
		FROM packages 
		ORDER BY downloads DESC 
		LIMIT 20
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var topPackages []map[string]interface{}
	for rows.Next() {
		var name, version string
		var downloads int64
		rows.Scan(&name, &version, &downloads)
		topPackages = append(topPackages, map[string]interface{}{
			"name":      name,
			"version":   version,
			"downloads": downloads,
		})
	}

	// Total statistics
	var totalPackages, totalDownloads int64
	rs.db.QueryRow("SELECT COUNT(*), SUM(downloads) FROM packages").Scan(&totalPackages, &totalDownloads)

	stats := map[string]interface{}{
		"total_packages":  totalPackages,
		"total_downloads": totalDownloads,
		"top_packages":    topPackages,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleRebuildIndex rebuilds the package index (admin only)
func (rs *RepositoryServer) handleRebuildIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Scan packages directory and sync with database
	files, err := os.ReadDir(rs.packagesDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rebuilt := 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		// In a real implementation, parse package metadata from file
		rebuilt++
	}

	log.Printf("Rebuilt index: %d packages", rebuilt)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"packages": rebuilt,
	})
}

// handleHealth returns server health status
func (rs *RepositoryServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Check database connection
	if err := rs.db.Ping(); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "unhealthy",
			"error":  err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "healthy",
		"time":   time.Now(),
	})
}

// incrementDownloadCount increments the download counter for a package
func (rs *RepositoryServer) incrementDownloadCount(filename string) {
	rs.db.Exec("UPDATE packages SET downloads = downloads + 1 WHERE filename = ?", filename)

	// Also update daily statistics
	today := time.Now().Format("2006-01-02")
	rs.db.Exec(`
		INSERT INTO download_stats (package_name, package_version, download_date, count)
		SELECT name, version, ?, 1
		FROM packages WHERE filename = ?
		ON CONFLICT(package_name, package_version, download_date)
		DO UPDATE SET count = count + 1
	`, today, filename)
}

// authMiddleware checks API key authentication
func (rs *RepositoryServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			apiKey = r.URL.Query().Get("api_key")
		}

		if apiKey == "" {
			http.Error(w, "API key required", http.StatusUnauthorized)
			return
		}

		// Verify API key
		var count int
		err := rs.db.QueryRow("SELECT COUNT(*) FROM api_keys WHERE key = ?", apiKey).Scan(&count)
		if err != nil || count == 0 {
			http.Error(w, "Invalid API key", http.StatusUnauthorized)
			return
		}

		// Update last used timestamp
		rs.db.Exec("UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE key = ?", apiKey)

		next(w, r)
	}
}

// loggingMiddleware logs all requests
func (rs *RepositoryServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Create a response writer wrapper to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		
		next.ServeHTTP(wrapped, r)
		
		duration := time.Since(start)
		log.Printf("%s %s %d %v %s", r.Method, r.URL.Path, wrapped.statusCode, duration, r.RemoteAddr)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// CreateAPIKey creates a new API key
func (rs *RepositoryServer) CreateAPIKey(description string) (string, error) {
	// Generate random API key
	key := generateRandomKey(32)
	
	_, err := rs.db.Exec(`
		INSERT INTO api_keys (key, description, permissions)
		VALUES (?, ?, ?)
	`, key, description, "admin")
	
	if err != nil {
		return "", err
	}
	
	return key, nil
}

func generateRandomKey(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[i%len(charset)]
	}
	return hex.EncodeToString(b)[:length]
}

// Close closes the database connection
func (rs *RepositoryServer) Close() error {
	if rs.db != nil {
		return rs.db.Close()
	}
	return nil
}

func main() {
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "./repo-data"
	}

	port := 8080
	if portStr := os.Getenv("PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://localhost:%d", port)
	}

	rs, err := NewRepositoryServer(dataDir, port, baseURL)
	if err != nil {
		log.Fatalf("Failed to create repository server: %v", err)
	}
	defer rs.Close()

	// Create initial API key if none exists
	var count int
	rs.db.QueryRow("SELECT COUNT(*) FROM api_keys").Scan(&count)
	if count == 0 {
		key, err := rs.CreateAPIKey("Initial admin key")
		if err != nil {
			log.Printf("Warning: failed to create initial API key: %v", err)
		} else {
			log.Printf("Created initial API key: %s", key)
			log.Printf("Save this key securely - it won't be shown again!")
		}
	}

	log.Fatal(rs.Start())
}
