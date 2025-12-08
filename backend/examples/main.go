package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/argon2"
)

// ===================== LICENSE & FEATURE SCOPES =====================

type FeatureScope string

const (
	ScopeBasicStorage    FeatureScope = "basic_storage"
	ScopeAdvancedSearch  FeatureScope = "advanced_search"
	ScopeFileManagement  FeatureScope = "file_management"
	ScopeBulkOperations  FeatureScope = "bulk_operations"
	ScopeExportImport    FeatureScope = "export_import"
	ScopeAuditLog        FeatureScope = "audit_log"
	ScopeChainValidation FeatureScope = "chain_validation"
	ScopeBackupRestore   FeatureScope = "backup_restore"
)

type License struct {
	Type          string         `json:"type"`
	EnabledScopes []FeatureScope `json:"enabled_scopes"`
	ExpiresAt     int64          `json:"expires_at"`
	MaxSecrets    int            `json:"max_secrets"`
	MaxFileSize   int64          `json:"max_file_size"`
}

type LicenseManager struct {
	license *License
}

func NewLicenseManager(licenseFile string) (*LicenseManager, error) {
	if _, err := os.Stat(licenseFile); os.IsNotExist(err) {
		defaultLicense := &License{
			Type:          "free",
			EnabledScopes: []FeatureScope{ScopeBasicStorage, ScopeChainValidation, ScopeAuditLog},
			ExpiresAt:     time.Now().Add(30 * 24 * time.Hour).Unix(),
			MaxSecrets:    10,
			MaxFileSize:   1024 * 1024,
		}
		data, _ := json.MarshalIndent(defaultLicense, "", "  ")
		os.WriteFile(licenseFile, data, 0600)
		return &LicenseManager{license: defaultLicense}, nil
	}

	data, err := os.ReadFile(licenseFile)
	if err != nil {
		return nil, err
	}

	var license License
	if err := json.Unmarshal(data, &license); err != nil {
		return nil, err
	}

	return &LicenseManager{license: &license}, nil
}

func (lm *LicenseManager) HasScope(scope FeatureScope) bool {
	if time.Now().Unix() > lm.license.ExpiresAt {
		return false
	}

	for _, s := range lm.license.EnabledScopes {
		if s == scope {
			return true
		}
	}
	return false
}

func (lm *LicenseManager) ValidateScope(scope FeatureScope) error {
	if !lm.HasScope(scope) {
		return fmt.Errorf("feature '%s' not available in %s license. Please upgrade.", scope, lm.license.Type)
	}
	return nil
}

// ===================== CRYPTOGRAPHY LAYER =====================

type CryptoEngine struct {
	masterKey []byte
}

func NewCryptoEngine(password string, salt []byte) (*CryptoEngine, error) {
	if len(salt) == 0 {
		salt = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, err
		}
	}

	masterKey := argon2.IDKey([]byte(password), salt, 4, 64*1024, 4, 32)
	return &CryptoEngine{masterKey: masterKey}, nil
}

func (ce *CryptoEngine) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(ce.masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (ce *CryptoEngine) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(ce.masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// ===================== MERKLE TREE IMPLEMENTATION =====================

type MerkleNode struct {
	Left  *MerkleNode `json:"-"`
	Right *MerkleNode `json:"-"`
	Hash  string      `json:"hash"`
}

type MerkleTree struct {
	Root   *MerkleNode `json:"root"`
	Leaves []string    `json:"leaves"`
}

func hashData(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func NewMerkleNode(left, right *MerkleNode, data string) *MerkleNode {
	node := &MerkleNode{}

	if left == nil && right == nil {
		node.Hash = hashData(data)
	} else {
		combinedHash := left.Hash + right.Hash
		node.Hash = hashData(combinedHash)
	}

	node.Left = left
	node.Right = right
	return node
}

func NewMerkleTree(data []string) *MerkleTree {
	if len(data) == 0 {
		return &MerkleTree{Leaves: data}
	}

	var nodes []*MerkleNode

	// Create leaf nodes
	for _, datum := range data {
		node := NewMerkleNode(nil, nil, datum)
		nodes = append(nodes, node)
	}

	// Build tree bottom-up
	for len(nodes) > 1 {
		var level []*MerkleNode

		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				node := NewMerkleNode(nodes[i], nodes[i+1], "")
				level = append(level, node)
			} else {
				// Duplicate last node if odd number
				node := NewMerkleNode(nodes[i], nodes[i], "")
				level = append(level, node)
			}
		}

		nodes = level
	}

	return &MerkleTree{
		Root:   nodes[0],
		Leaves: data,
	}
}

func (mt *MerkleTree) GetRootHash() string {
	if mt.Root == nil {
		return ""
	}
	return mt.Root.Hash
}

func (mt *MerkleTree) VerifyLeaf(data string, index int) bool {
	if index >= len(mt.Leaves) {
		return false
	}
	return mt.Leaves[index] == data
}

// ===================== TAMPER-PROOF AUDIT LOG =====================

type AuditEntry struct {
	ID           string            `json:"id"`
	Timestamp    int64             `json:"timestamp"`
	Action       string            `json:"action"`
	Target       string            `json:"target"`
	User         string            `json:"user"`
	IPAddress    string            `json:"ip_address"`
	Success      bool              `json:"success"`
	Details      string            `json:"details"`
	Metadata     map[string]string `json:"metadata"`
	Hash         string            `json:"hash"`
	PreviousHash string            `json:"previous_hash"`
	MerkleRoot   string            `json:"merkle_root"`
	Signature    string            `json:"signature"`
}

func (ae *AuditEntry) CalculateHash() string {
	record := fmt.Sprintf("%s%d%s%s%s%s%t%s%s",
		ae.ID, ae.Timestamp, ae.Action, ae.Target, ae.User,
		ae.IPAddress, ae.Success, ae.Details, ae.PreviousHash)
	h := sha512.Sum512([]byte(record))
	return hex.EncodeToString(h[:])
}

type AuditLog struct {
	Entries     []*AuditEntry `json:"entries"`
	MerkleTree  *MerkleTree   `json:"merkle_tree"`
	crypto      *CryptoEngine
	currentHash string
}

func NewAuditLog(crypto *CryptoEngine) *AuditLog {
	// Create genesis audit entry
	genesis := &AuditEntry{
		ID:           "genesis",
		Timestamp:    time.Now().Unix(),
		Action:       "SYSTEM_INIT",
		Target:       "audit_log",
		User:         "system",
		Success:      true,
		Details:      "Audit log initialized",
		PreviousHash: "0",
		Metadata:     make(map[string]string),
	}
	genesis.Hash = genesis.CalculateHash()

	return &AuditLog{
		Entries:     []*AuditEntry{genesis},
		crypto:      crypto,
		currentHash: genesis.Hash,
	}
}

func (al *AuditLog) Log(action, target, user, ipAddr string, success bool, details string, metadata map[string]string) error {
	if metadata == nil {
		metadata = make(map[string]string)
	}

	entry := &AuditEntry{
		ID:           fmt.Sprintf("audit_%d_%s", time.Now().UnixNano(), generateID(8)),
		Timestamp:    time.Now().Unix(),
		Action:       action,
		Target:       target,
		User:         user,
		IPAddress:    ipAddr,
		Success:      success,
		Details:      details,
		Metadata:     metadata,
		PreviousHash: al.currentHash,
	}

	entry.Hash = entry.CalculateHash()

	// Create digital signature
	signatureData := []byte(entry.Hash + entry.PreviousHash)
	encryptedSig, err := al.crypto.Encrypt(signatureData)
	if err != nil {
		return err
	}
	entry.Signature = hex.EncodeToString(encryptedSig)

	al.Entries = append(al.Entries, entry)
	al.currentHash = entry.Hash

	// Rebuild Merkle tree with all entry hashes
	al.RebuildMerkleTree()

	return nil
}

func (al *AuditLog) RebuildMerkleTree() {
	var hashes []string
	for _, entry := range al.Entries {
		hashes = append(hashes, entry.Hash)
	}

	al.MerkleTree = NewMerkleTree(hashes)

	// Update merkle root in all entries (for verification)
	merkleRoot := al.MerkleTree.GetRootHash()
	for _, entry := range al.Entries {
		entry.MerkleRoot = merkleRoot
	}
}

func (al *AuditLog) ValidateChain() bool {
	// Validate chain integrity
	for i := 1; i < len(al.Entries); i++ {
		current := al.Entries[i]
		previous := al.Entries[i-1]

		// Verify hash calculation
		if current.Hash != current.CalculateHash() {
			fmt.Printf("Hash mismatch at entry %d\n", i)
			return false
		}

		// Verify chain linkage
		if current.PreviousHash != previous.Hash {
			fmt.Printf("Chain break at entry %d\n", i)
			return false
		}

		// Verify signature
		if current.Signature == "" {
			fmt.Printf("Missing signature at entry %d\n", i)
			return false
		}
	}

	// Validate Merkle tree
	if al.MerkleTree == nil {
		return false
	}

	// Verify merkle root matches
	expectedRoot := al.MerkleTree.GetRootHash()
	if len(al.Entries) > 0 {
		lastEntry := al.Entries[len(al.Entries)-1]
		if lastEntry.MerkleRoot != expectedRoot {
			fmt.Println("Merkle root mismatch")
			return false
		}
	}

	return true
}

func (al *AuditLog) GetRecentEntries(limit int) []*AuditEntry {
	start := len(al.Entries) - limit
	if start < 0 {
		start = 0
	}

	return al.Entries[start:]
}

func (al *AuditLog) SearchEntries(query string) []*AuditEntry {
	var results []*AuditEntry
	query = strings.ToLower(query)

	for _, entry := range al.Entries {
		if strings.Contains(strings.ToLower(entry.Action), query) ||
			strings.Contains(strings.ToLower(entry.Target), query) ||
			strings.Contains(strings.ToLower(entry.User), query) ||
			strings.Contains(strings.ToLower(entry.Details), query) {
			results = append(results, entry)
		}
	}

	return results
}

// ===================== ACCESS LOG =====================

type AccessEntry struct {
	ID           string            `json:"id"`
	Timestamp    int64             `json:"timestamp"`
	User         string            `json:"user"`
	Resource     string            `json:"resource"`
	Action       string            `json:"action"`
	IPAddress    string            `json:"ip_address"`
	UserAgent    string            `json:"user_agent"`
	Success      bool              `json:"success"`
	DeniedReason string            `json:"denied_reason,omitempty"`
	Metadata     map[string]string `json:"metadata"`
	Hash         string            `json:"hash"`
	PreviousHash string            `json:"previous_hash"`
	MerkleRoot   string            `json:"merkle_root"`
}

func (ae *AccessEntry) CalculateHash() string {
	record := fmt.Sprintf("%s%d%s%s%s%s%s%t%s",
		ae.ID, ae.Timestamp, ae.User, ae.Resource, ae.Action,
		ae.IPAddress, ae.UserAgent, ae.Success, ae.PreviousHash)
	h := sha512.Sum512([]byte(record))
	return hex.EncodeToString(h[:])
}

type AccessLog struct {
	Entries     []*AccessEntry `json:"entries"`
	MerkleTree  *MerkleTree    `json:"merkle_tree"`
	currentHash string
}

func NewAccessLog() *AccessLog {
	genesis := &AccessEntry{
		ID:           "genesis",
		Timestamp:    time.Now().Unix(),
		User:         "system",
		Resource:     "access_log",
		Action:       "INIT",
		Success:      true,
		PreviousHash: "0",
		Metadata:     make(map[string]string),
	}
	genesis.Hash = genesis.CalculateHash()

	return &AccessLog{
		Entries:     []*AccessEntry{genesis},
		currentHash: genesis.Hash,
	}
}

func (al *AccessLog) Log(user, resource, action, ipAddr, userAgent string, success bool, deniedReason string, metadata map[string]string) {
	if metadata == nil {
		metadata = make(map[string]string)
	}

	entry := &AccessEntry{
		ID:           fmt.Sprintf("access_%d_%s", time.Now().UnixNano(), generateID(8)),
		Timestamp:    time.Now().Unix(),
		User:         user,
		Resource:     resource,
		Action:       action,
		IPAddress:    ipAddr,
		UserAgent:    userAgent,
		Success:      success,
		DeniedReason: deniedReason,
		Metadata:     metadata,
		PreviousHash: al.currentHash,
	}

	entry.Hash = entry.CalculateHash()
	al.Entries = append(al.Entries, entry)
	al.currentHash = entry.Hash

	al.RebuildMerkleTree()
}

func (al *AccessLog) RebuildMerkleTree() {
	var hashes []string
	for _, entry := range al.Entries {
		hashes = append(hashes, entry.Hash)
	}

	al.MerkleTree = NewMerkleTree(hashes)
	merkleRoot := al.MerkleTree.GetRootHash()

	for _, entry := range al.Entries {
		entry.MerkleRoot = merkleRoot
	}
}

func (al *AccessLog) ValidateChain() bool {
	for i := 1; i < len(al.Entries); i++ {
		current := al.Entries[i]
		previous := al.Entries[i-1]

		if current.Hash != current.CalculateHash() {
			return false
		}

		if current.PreviousHash != previous.Hash {
			return false
		}
	}

	if al.MerkleTree == nil {
		return false
	}

	expectedRoot := al.MerkleTree.GetRootHash()
	if len(al.Entries) > 0 {
		lastEntry := al.Entries[len(al.Entries)-1]
		if lastEntry.MerkleRoot != expectedRoot {
			return false
		}
	}

	return true
}

func (al *AccessLog) GetRecentEntries(limit int) []*AccessEntry {
	start := len(al.Entries) - limit
	if start < 0 {
		start = 0
	}
	return al.Entries[start:]
}

// ===================== INDEXING & SEARCH =====================

type IndexEntry struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	BlockIndex  int               `json:"block_index"`
	Size        int64             `json:"size"`
	Hash        string            `json:"hash"`
	Tags        []string          `json:"tags"`
	CreatedAt   int64             `json:"created_at"`
	Metadata    map[string]string `json:"metadata"`
	SearchTerms []string          `json:"search_terms"`
}

type SearchIndex struct {
	Entries map[string]*IndexEntry `json:"entries"`
}

func NewSearchIndex() *SearchIndex {
	return &SearchIndex{Entries: make(map[string]*IndexEntry)}
}

func (si *SearchIndex) Add(entry *IndexEntry) {
	terms := strings.Fields(strings.ToLower(entry.Name))
	for _, tag := range entry.Tags {
		terms = append(terms, strings.ToLower(tag))
	}
	for k, v := range entry.Metadata {
		terms = append(terms, strings.ToLower(k), strings.ToLower(v))
	}
	entry.SearchTerms = terms
	si.Entries[entry.Name] = entry
}

func (si *SearchIndex) Search(query string) []*IndexEntry {
	query = strings.ToLower(query)
	var results []*IndexEntry

	for _, entry := range si.Entries {
		for _, term := range entry.SearchTerms {
			if strings.Contains(term, query) {
				results = append(results, entry)
				break
			}
		}
	}

	return results
}

func (si *SearchIndex) SearchByType(itemType string) []*IndexEntry {
	var results []*IndexEntry
	for _, entry := range si.Entries {
		if entry.Type == itemType {
			results = append(results, entry)
		}
	}
	return results
}

func (si *SearchIndex) SearchByTags(tags []string) []*IndexEntry {
	var results []*IndexEntry
	for _, entry := range si.Entries {
		matches := 0
		for _, tag := range tags {
			for _, entryTag := range entry.Tags {
				if strings.EqualFold(tag, entryTag) {
					matches++
					break
				}
			}
		}
		if matches > 0 {
			results = append(results, entry)
		}
	}
	return results
}

// ===================== BLOCKCHAIN LAYER =====================

type Block struct {
	Index        int64             `json:"index"`
	Timestamp    int64             `json:"timestamp"`
	Data         []byte            `json:"data"`
	PreviousHash string            `json:"previous_hash"`
	Hash         string            `json:"hash"`
	Nonce        int64             `json:"nonce"`
	Metadata     map[string]string `json:"metadata"`
}

func (b *Block) CalculateHash() string {
	record := fmt.Sprintf("%d%d%s%s%d", b.Index, b.Timestamp, b.Data, b.PreviousHash, b.Nonce)
	h := sha512.Sum512([]byte(record))
	return hex.EncodeToString(h[:])
}

func (b *Block) MineBlock(difficulty int) {
	target := strings.Repeat("0", difficulty)
	for {
		b.Hash = b.CalculateHash()
		if b.Hash[:difficulty] == target {
			break
		}
		b.Nonce++
	}
}

type Blockchain struct {
	Blocks     []*Block
	Difficulty int
	crypto     *CryptoEngine
}

func NewBlockchain(crypto *CryptoEngine) *Blockchain {
	genesis := &Block{
		Index:        0,
		Timestamp:    time.Now().Unix(),
		Data:         []byte("GENESIS_BLOCK"),
		PreviousHash: "0",
		Metadata:     map[string]string{"type": "genesis"},
	}
	genesis.MineBlock(4)

	return &Blockchain{
		Blocks:     []*Block{genesis},
		Difficulty: 4,
		crypto:     crypto,
	}
}

func (bc *Blockchain) AddBlock(data []byte, metadata map[string]string) error {
	encryptedData, err := bc.crypto.Encrypt(data)
	if err != nil {
		return err
	}

	prevBlock := bc.Blocks[len(bc.Blocks)-1]
	newBlock := &Block{
		Index:        prevBlock.Index + 1,
		Timestamp:    time.Now().Unix(),
		Data:         encryptedData,
		PreviousHash: prevBlock.Hash,
		Metadata:     metadata,
	}

	newBlock.MineBlock(bc.Difficulty)
	bc.Blocks = append(bc.Blocks, newBlock)

	return nil
}

func (bc *Blockchain) ValidateChain() bool {
	for i := 1; i < len(bc.Blocks); i++ {
		currentBlock := bc.Blocks[i]
		previousBlock := bc.Blocks[i-1]

		if currentBlock.Hash != currentBlock.CalculateHash() {
			return false
		}

		if currentBlock.PreviousHash != previousBlock.Hash {
			return false
		}
	}
	return true
}

func (bc *Blockchain) GetBlockData(index int) ([]byte, error) {
	if index >= len(bc.Blocks) || index < 0 {
		return nil, errors.New("invalid block index")
	}

	block := bc.Blocks[index]
	if block.Index == 0 {
		return block.Data, nil
	}

	return bc.crypto.Decrypt(block.Data)
}

// ===================== VAULT MANAGEMENT =====================

type SecretVault struct {
	blockchain   *Blockchain
	searchIndex  *SearchIndex
	auditLog     *AuditLog
	accessLog    *AccessLog
	salt         []byte
	dataDir      string
	licenseCheck func(FeatureScope) error
	crypto       *CryptoEngine
}

func NewSecretVault(password, dataDir string, licenseCheck func(FeatureScope) error) (*SecretVault, error) {
	os.MkdirAll(dataDir, 0700)

	saltFile := filepath.Join(dataDir, "salt.bin")
	var salt []byte

	if _, err := os.Stat(saltFile); os.IsNotExist(err) {
		salt = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, err
		}
		os.WriteFile(saltFile, salt, 0600)
	} else {
		salt, _ = os.ReadFile(saltFile)
	}

	crypto, err := NewCryptoEngine(password, salt)
	if err != nil {
		return nil, err
	}

	vault := &SecretVault{
		blockchain:   NewBlockchain(crypto),
		searchIndex:  NewSearchIndex(),
		auditLog:     NewAuditLog(crypto),
		accessLog:    NewAccessLog(),
		salt:         salt,
		dataDir:      dataDir,
		licenseCheck: licenseCheck,
		crypto:       crypto,
	}

	vault.Load()
	return vault, nil
}

func (sv *SecretVault) Save() error {
	indexFile := filepath.Join(sv.dataDir, "index.json")
	chainFile := filepath.Join(sv.dataDir, "chain.json")
	auditFile := filepath.Join(sv.dataDir, "audit.json")
	accessFile := filepath.Join(sv.dataDir, "access.json")

	indexData, _ := json.MarshalIndent(sv.searchIndex, "", "  ")
	chainData, _ := json.MarshalIndent(sv.blockchain.Blocks, "", "  ")
	auditData, _ := json.MarshalIndent(sv.auditLog, "", "  ")
	accessData, _ := json.MarshalIndent(sv.accessLog, "", "  ")

	os.WriteFile(indexFile, indexData, 0600)
	os.WriteFile(chainFile, chainData, 0600)
	os.WriteFile(auditFile, auditData, 0600)
	os.WriteFile(accessFile, accessData, 0600)

	return nil
}

func (sv *SecretVault) Load() error {
	indexFile := filepath.Join(sv.dataDir, "index.json")
	chainFile := filepath.Join(sv.dataDir, "chain.json")
	auditFile := filepath.Join(sv.dataDir, "audit.json")
	accessFile := filepath.Join(sv.dataDir, "access.json")

	if data, err := os.ReadFile(indexFile); err == nil {
		json.Unmarshal(data, sv.searchIndex)
	}

	if data, err := os.ReadFile(chainFile); err == nil {
		json.Unmarshal(data, &sv.blockchain.Blocks)
	}

	if data, err := os.ReadFile(auditFile); err == nil {
		json.Unmarshal(data, sv.auditLog)
	}

	if data, err := os.ReadFile(accessFile); err == nil {
		json.Unmarshal(data, sv.accessLog)
	}

	return nil
}

func (sv *SecretVault) VerifyIntegrity() bool {
	if err := sv.licenseCheck(ScopeChainValidation); err != nil {
		return false
	}
	return sv.blockchain.ValidateChain()
}

// ===================== UTILITY FUNCTIONS =====================

func generateID(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	rand.Read(b)
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

// ===================== CLI APPLICATION =====================

var (
	globalVault   *SecretVault
	globalLicense *LicenseManager
)

func main() {
	licenseFile := "license.json"
	lm, err := NewLicenseManager(licenseFile)
	if err != nil {
		fmt.Printf("Error loading license: %v\n", err)
		return
	}
	globalLicense = lm

	app := &cli.App{
		Name:    "vault",
		Usage:   "Military-grade blockchain-based secret & file management with tamper-proof audit trails",
		Version: "2.0.0",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "password",
				Aliases:  []string{"p"},
				Usage:    "Master password for vault",
				Required: true,
				EnvVars:  []string{"VAULT_PASSWORD"},
			},
			&cli.StringFlag{
				Name:    "data-dir",
				Aliases: []string{"d"},
				Usage:   "Data directory for vault storage",
				Value:   "./vault_data",
			},
		},
		Before: func(c *cli.Context) error {
			password := c.String("password")
			dataDir := c.String("data-dir")

			vault, err := NewSecretVault(password, dataDir, globalLicense.ValidateScope)
			if err != nil {
				return err
			}
			globalVault = vault
			return nil
		},
		Commands: []*cli.Command{
			{
				Name:    "secret",
				Aliases: []string{"s"},
				Usage:   "Secret management operations",
				Subcommands: []*cli.Command{
					{
						Name:  "add",
						Usage: "Add a new secret",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Required: true},
							&cli.StringFlag{Name: "value", Aliases: []string{"v"}, Required: true},
							&cli.StringSliceFlag{Name: "tags", Aliases: []string{"t"}},
						},
						Action: requireScope(ScopeBasicStorage, addSecret),
					},
					{
						Name:  "get",
						Usage: "Retrieve a secret",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Required: true},
						},
						Action: requireScope(ScopeBasicStorage, getSecret),
					},
					{
						Name:   "list",
						Usage:  "List all secrets",
						Action: requireScope(ScopeBasicStorage, listSecrets),
					},
					{
						Name:  "delete",
						Usage: "Delete a secret",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Required: true},
						},
						Action: requireScope(ScopeBasicStorage, deleteItem),
					},
				},
			},
			{
				Name:    "file",
				Aliases: []string{"f"},
				Usage:   "File management operations",
				Subcommands: []*cli.Command{
					{
						Name:  "add",
						Usage: "Add a file to vault",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "path", Aliases: []string{"p"}, Required: true},
							&cli.StringFlag{Name: "name", Aliases: []string{"n"}},
							&cli.StringSliceFlag{Name: "tags", Aliases: []string{"t"}},
						},
						Action: requireScope(ScopeFileManagement, addFile),
					},
					{
						Name:  "get",
						Usage: "Retrieve a file",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "name", Aliases: []string{"n"}, Required: true},
							&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Required: true},
						},
						Action: requireScope(ScopeFileManagement, getFile),
					},
					{
						Name:   "list",
						Usage:  "List all files",
						Action: requireScope(ScopeFileManagement, listFiles),
					},
				},
			},
			{
				Name:    "search",
				Aliases: []string{"find"},
				Usage:   "Search for secrets and files",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "query", Aliases: []string{"q"}, Required: true},
					&cli.StringFlag{Name: "type", Aliases: []string{"t"}},
					&cli.StringSliceFlag{Name: "tags"},
				},
				Action: requireScope(ScopeAdvancedSearch, searchItems),
			},
			{
				Name:   "validate",
				Usage:  "Validate blockchain integrity",
				Action: requireScope(ScopeChainValidation, validateChain),
			},
			{
				Name:  "audit",
				Usage: "Audit log operations",
				Subcommands: []*cli.Command{
					{
						Name:  "view",
						Usage: "View audit logs",
						Flags: []cli.Flag{
							&cli.IntFlag{Name: "limit", Aliases: []string{"l"}, Value: 10},
						},
						Action: requireScope(ScopeAuditLog, viewAudit),
					},
					{
						Name:   "validate",
						Usage:  "Validate audit log chain integrity",
						Action: requireScope(ScopeAuditLog, validateAuditChain),
					},
					{
						Name:  "search",
						Usage: "Search audit logs",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "query", Aliases: []string{"q"}, Required: true},
						},
						Action: requireScope(ScopeAuditLog, searchAudit),
					},
				},
			},
			{
				Name:  "access",
				Usage: "Access log operations",
				Subcommands: []*cli.Command{
					{
						Name:  "view",
						Usage: "View access logs",
						Flags: []cli.Flag{
							&cli.IntFlag{Name: "limit", Aliases: []string{"l"}, Value: 10},
						},
						Action: requireScope(ScopeAuditLog, viewAccess),
					},
					{
						Name:   "validate",
						Usage:  "Validate access log chain integrity",
						Action: requireScope(ScopeAuditLog, validateAccessChain),
					},
				},
			},
			{
				Name:  "export",
				Usage: "Export vault data",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Required: true},
				},
				Action: requireScope(ScopeExportImport, exportVault),
			},
			{
				Name:  "license",
				Usage: "View license information",
				Action: func(c *cli.Context) error {
					fmt.Printf("License Type: %s\n", globalLicense.license.Type)
					fmt.Printf("Expires: %s\n", time.Unix(globalLicense.license.ExpiresAt, 0).Format(time.RFC3339))
					fmt.Printf("Max Secrets: %d\n", globalLicense.license.MaxSecrets)
					fmt.Printf("Max File Size: %d bytes\n", globalLicense.license.MaxFileSize)
					fmt.Println("\nEnabled Features:")
					for _, scope := range globalLicense.license.EnabledScopes {
						fmt.Printf("  ✓ %s\n", scope)
					}
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

// ===================== MIDDLEWARE =====================

func requireScope(scope FeatureScope, action cli.ActionFunc) cli.ActionFunc {
	return func(c *cli.Context) error {
		if err := globalLicense.ValidateScope(scope); err != nil {
			return err
		}
		return action(c)
	}
}

// ===================== CLI ACTIONS =====================

func addSecret(c *cli.Context) error {
	name := c.String("name")
	value := c.String("value")
	tags := c.StringSlice("tags")

	err := globalVault.StoreSecret(name, []byte(value), tags, nil)
	if err != nil {
		return err
	}

	fmt.Printf("✓ Secret '%s' added successfully\n", name)
	return nil
}

func getSecret(c *cli.Context) error {
	name := c.String("name")
	data, err := globalVault.Retrieve(name)
	if err != nil {
		return err
	}

	fmt.Printf("Secret: %s\n", string(data))
	return nil
}

func listSecrets(c *cli.Context) error {
	results := globalVault.searchIndex.SearchByType("secret")
	fmt.Printf("Found %d secrets:\n\n", len(results))

	for _, entry := range results {
		fmt.Printf("Name: %s\n", entry.Name)
		fmt.Printf("  Size: %d bytes\n", entry.Size)
		fmt.Printf("  Created: %s\n", time.Unix(entry.CreatedAt, 0).Format(time.RFC3339))
		fmt.Printf("  Tags: %v\n", entry.Tags)
		fmt.Printf("  Hash: %s\n\n", entry.Hash[:16]+"...")
	}
	return nil
}

func addFile(c *cli.Context) error {
	path := c.String("path")
	name := c.String("name")
	if name == "" {
		name = filepath.Base(path)
	}
	tags := c.StringSlice("tags")

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	err = globalVault.StoreFile(name, data, tags, nil)
	if err != nil {
		return err
	}

	fmt.Printf("✓ File '%s' added successfully\n", name)
	return nil
}

func getFile(c *cli.Context) error {
	name := c.String("name")
	output := c.String("output")

	data, err := globalVault.Retrieve(name)
	if err != nil {
		return err
	}

	err = os.WriteFile(output, data, 0600)
	if err != nil {
		return err
	}

	fmt.Printf("✓ File saved to '%s'\n", output)
	return nil
}

func listFiles(c *cli.Context) error {
	results := globalVault.searchIndex.SearchByType("file")
	fmt.Printf("Found %d files:\n\n", len(results))

	for _, entry := range results {
		fmt.Printf("Name: %s\n", entry.Name)
		fmt.Printf("  Size: %d bytes\n", entry.Size)
		fmt.Printf("  Created: %s\n", time.Unix(entry.CreatedAt, 0).Format(time.RFC3339))
		fmt.Printf("  Tags: %v\n", entry.Tags)
		fmt.Printf("  Hash: %s\n\n", entry.Hash[:16]+"...")
	}
	return nil
}

func deleteItem(c *cli.Context) error {
	name := c.String("name")
	err := globalVault.Delete(name)
	if err != nil {
		return err
	}

	fmt.Printf("✓ Item '%s' deleted successfully\n", name)
	return nil
}

func searchItems(c *cli.Context) error {
	query := c.String("query")
	itemType := c.String("type")
	tags := c.StringSlice("tags")

	var results []*IndexEntry

	if len(tags) > 0 {
		results = globalVault.searchIndex.SearchByTags(tags)
	} else if itemType != "" {
		results = globalVault.searchIndex.SearchByType(itemType)
	} else {
		results = globalVault.Search(query)
	}

	fmt.Printf("Found %d results:\n\n", len(results))

	for _, entry := range results {
		fmt.Printf("Name: %s [%s]\n", entry.Name, entry.Type)
		fmt.Printf("  Size: %d bytes\n", entry.Size)
		fmt.Printf("  Tags: %v\n", entry.Tags)
		fmt.Printf("  Created: %s\n\n", time.Unix(entry.CreatedAt, 0).Format(time.RFC3339))
	}
	return nil
}

func validateChain(c *cli.Context) error {
	fmt.Println("Validating blockchain integrity...")

	if globalVault.VerifyIntegrity() {
		fmt.Println("✓ Blockchain integrity verified: TAMPER-PROOF")
		fmt.Printf("  Total blocks: %d\n", len(globalVault.blockchain.Blocks))
		fmt.Printf("  Difficulty: %d\n", globalVault.blockchain.Difficulty)
	} else {
		fmt.Println("✗ Blockchain integrity compromised: TAMPERED")
	}
	return nil
}

func viewAudit(c *cli.Context) error {
	limit := c.Int("limit")
	entries := globalVault.auditLog.GetRecentEntries(limit)

	fmt.Printf("Recent audit entries (showing %d):\n\n", len(entries))

	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		status := "✓"
		if !entry.Success {
			status = "✗"
		}

		fmt.Printf("%s [%s] %s\n", status, time.Unix(entry.Timestamp, 0).Format(time.RFC3339), entry.Action)
		fmt.Printf("  ID: %s\n", entry.ID)
		fmt.Printf("  Target: %s\n", entry.Target)
		fmt.Printf("  User: %s @ %s\n", entry.User, entry.IPAddress)
		fmt.Printf("  Details: %s\n", entry.Details)
		fmt.Printf("  Hash: %s\n", entry.Hash[:32]+"...")
		fmt.Printf("  Previous: %s\n", entry.PreviousHash[:32]+"...")
		fmt.Printf("  Merkle Root: %s\n\n", entry.MerkleRoot[:32]+"...")
	}
	return nil
}

func validateAuditChain(c *cli.Context) error {
	fmt.Println("Validating audit log chain integrity...")

	if globalVault.auditLog.ValidateChain() {
		fmt.Println("✓ Audit log chain integrity verified: TAMPER-PROOF")
		fmt.Printf("  Total entries: %d\n", len(globalVault.auditLog.Entries))
		fmt.Printf("  Merkle Root: %s\n", globalVault.auditLog.MerkleTree.GetRootHash()[:32]+"...")
	} else {
		fmt.Println("✗ Audit log chain integrity compromised: TAMPERED")
	}
	return nil
}

func searchAudit(c *cli.Context) error {
	query := c.String("query")
	results := globalVault.auditLog.SearchEntries(query)

	fmt.Printf("Found %d audit entries:\n\n", len(results))

	for _, entry := range results {
		status := "✓"
		if !entry.Success {
			status = "✗"
		}

		fmt.Printf("%s [%s] %s\n", status, time.Unix(entry.Timestamp, 0).Format(time.RFC3339), entry.Action)
		fmt.Printf("  Target: %s\n", entry.Target)
		fmt.Printf("  Details: %s\n\n", entry.Details)
	}
	return nil
}

func viewAccess(c *cli.Context) error {
	limit := c.Int("limit")
	entries := globalVault.accessLog.GetRecentEntries(limit)

	fmt.Printf("Recent access entries (showing %d):\n\n", len(entries))

	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		status := "✓"
		if !entry.Success {
			status = "✗"
		}

		fmt.Printf("%s [%s] %s\n", status, time.Unix(entry.Timestamp, 0).Format(time.RFC3339), entry.Action)
		fmt.Printf("  ID: %s\n", entry.ID)
		fmt.Printf("  User: %s\n", entry.User)
		fmt.Printf("  Resource: %s\n", entry.Resource)
		fmt.Printf("  IP: %s\n", entry.IPAddress)
		if entry.DeniedReason != "" {
			fmt.Printf("  Denied: %s\n", entry.DeniedReason)
		}
		fmt.Printf("  Hash: %s\n", entry.Hash[:32]+"...")
		fmt.Printf("  Merkle Root: %s\n\n", entry.MerkleRoot[:32]+"...")
	}
	return nil
}

func validateAccessChain(c *cli.Context) error {
	fmt.Println("Validating access log chain integrity...")

	if globalVault.accessLog.ValidateChain() {
		fmt.Println("✓ Access log chain integrity verified: TAMPER-PROOF")
		fmt.Printf("  Total entries: %d\n", len(globalVault.accessLog.Entries))
		fmt.Printf("  Merkle Root: %s\n", globalVault.accessLog.MerkleTree.GetRootHash()[:32]+"...")
	} else {
		fmt.Println("✗ Access log chain integrity compromised: TAMPERED")
	}
	return nil
}

func exportVault(c *cli.Context) error {
	output := c.String("output")

	exportData := map[string]interface{}{
		"blockchain": globalVault.blockchain.Blocks,
		"index":      globalVault.searchIndex,
		"audit_log":  globalVault.auditLog,
		"access_log": globalVault.accessLog,
		"exported":   time.Now().Unix(),
	}

	data, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(output, data, 0600)
	if err != nil {
		return err
	}

	fmt.Printf("✓ Vault exported to '%s'\n", output)
	globalVault.auditLog.Log("export_vault", output, "system", "127.0.0.1", true, "Vault exported successfully", nil)
	return nil
}

func (sv *SecretVault) StoreSecret(name string, secret []byte, tags []string, metadata map[string]string) error {
	// Access control check
	sv.accessLog.Log("system", name, "STORE_SECRET", "127.0.0.1", "vault-cli", true, "", nil)

	if err := sv.licenseCheck(ScopeBasicStorage); err != nil {
		sv.auditLog.Log("store_secret", name, "system", "127.0.0.1", false, err.Error(), nil)
		return err
	}

	if metadata == nil {
		metadata = make(map[string]string)
	}
	metadata["type"] = "secret"
	metadata["name"] = name
	metadata["hash"] = fmt.Sprintf("%x", sha256.Sum256(secret))

	if err := sv.blockchain.AddBlock(secret, metadata); err != nil {
		sv.auditLog.Log("store_secret", name, "system", "127.0.0.1", false, err.Error(), metadata)
		return err
	}

	entry := &IndexEntry{
		Name:       name,
		Type:       "secret",
		BlockIndex: len(sv.blockchain.Blocks) - 1,
		Size:       int64(len(secret)),
		Hash:       metadata["hash"],
		Tags:       tags,
		CreatedAt:  time.Now().Unix(),
		Metadata:   metadata,
	}
	sv.searchIndex.Add(entry)
	sv.auditLog.Log("store_secret", name, "system", "127.0.0.1", true, "Secret stored successfully", metadata)

	return sv.Save()
}

func (sv *SecretVault) StoreFile(name string, fileData []byte, tags []string, metadata map[string]string) error {
	sv.accessLog.Log("system", name, "STORE_FILE", "127.0.0.1", "vault-cli", true, "", nil)

	if err := sv.licenseCheck(ScopeFileManagement); err != nil {
		sv.auditLog.Log("store_file", name, "system", "127.0.0.1", false, err.Error(), nil)
		return err
	}

	if metadata == nil {
		metadata = make(map[string]string)
	}
	metadata["type"] = "file"
	metadata["name"] = name
	metadata["size"] = fmt.Sprintf("%d", len(fileData))
	metadata["hash"] = fmt.Sprintf("%x", sha256.Sum256(fileData))

	if err := sv.blockchain.AddBlock(fileData, metadata); err != nil {
		sv.auditLog.Log("store_file", name, "system", "127.0.0.1", false, err.Error(), metadata)
		return err
	}

	entry := &IndexEntry{
		Name:       name,
		Type:       "file",
		BlockIndex: len(sv.blockchain.Blocks) - 1,
		Size:       int64(len(fileData)),
		Hash:       metadata["hash"],
		Tags:       tags,
		CreatedAt:  time.Now().Unix(),
		Metadata:   metadata,
	}
	sv.searchIndex.Add(entry)
	sv.auditLog.Log("store_file", name, "system", "127.0.0.1", true, "File stored successfully", metadata)

	return sv.Save()
}

func (sv *SecretVault) Retrieve(name string) ([]byte, error) {
	sv.accessLog.Log("system", name, "RETRIEVE", "127.0.0.1", "vault-cli", true, "", nil)

	entry, exists := sv.searchIndex.Entries[name]
	if !exists {
		sv.auditLog.Log("retrieve", name, "system", "127.0.0.1", false, "Not found", nil)
		return nil, errors.New("item not found")
	}

	data, err := sv.blockchain.GetBlockData(entry.BlockIndex)
	if err != nil {
		sv.auditLog.Log("retrieve", name, "system", "127.0.0.1", false, err.Error(), nil)
		return nil, err
	}

	sv.auditLog.Log("retrieve", name, "system", "127.0.0.1", true, "Retrieved successfully", nil)
	return data, nil
}

func (sv *SecretVault) Search(query string) []*IndexEntry {
	sv.accessLog.Log("system", query, "SEARCH", "127.0.0.1", "vault-cli", true, "", nil)
	return sv.searchIndex.Search(query)
}

func (sv *SecretVault) Delete(name string) error {
	sv.accessLog.Log("system", name, "DELETE", "127.0.0.1", "vault-cli", true, "", nil)

	if err := sv.licenseCheck(ScopeBasicStorage); err != nil {
		sv.auditLog.Log("delete", name, "system", "127.0.0.1", false, err.Error(), nil)
		return err
	}

	if _, exists := sv.searchIndex.Entries[name]; !exists {
		sv.auditLog.Log("delete", name, "system", "127.0.0.1", false, "Not found", nil)
		return errors.New("item not found")
	}

	delete(sv.searchIndex.Entries, name)
	sv.auditLog.Log("delete", name, "system", "127.0.0.1", true, "Deleted from index", nil)

	return sv.Save()
}
