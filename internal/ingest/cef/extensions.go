package cef

// Standard CEF extension field mappings
// Reference: https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/pdfdocs/cef-implementation-standard/cef-implementation-standard.pdf

// ExtensionInfo describes a CEF extension field.
type ExtensionInfo struct {
	Category    string
	Field       string
	Description string
}

// StandardExtensions maps CEF extension keys to their semantic meaning.
var StandardExtensions = map[string]ExtensionInfo{
	// Source fields
	"src":   {Category: "source", Field: "ip", Description: "Source IP address"},
	"spt":   {Category: "source", Field: "port", Description: "Source port"},
	"smac":  {Category: "source", Field: "mac", Description: "Source MAC address"},
	"shost": {Category: "source", Field: "hostname", Description: "Source hostname"},
	"suser": {Category: "source", Field: "user", Description: "Source user name"},
	"suid":  {Category: "source", Field: "user_id", Description: "Source user ID"},

	// Destination fields
	"dst":   {Category: "destination", Field: "ip", Description: "Destination IP address"},
	"dpt":   {Category: "destination", Field: "port", Description: "Destination port"},
	"dmac":  {Category: "destination", Field: "mac", Description: "Destination MAC address"},
	"dhost": {Category: "destination", Field: "hostname", Description: "Destination hostname"},
	"duser": {Category: "destination", Field: "user", Description: "Destination user name"},
	"duid":  {Category: "destination", Field: "user_id", Description: "Destination user ID"},

	// Event fields
	"act":     {Category: "event", Field: "action", Description: "Action taken"},
	"outcome": {Category: "event", Field: "outcome", Description: "Event outcome"},
	"reason":  {Category: "event", Field: "reason", Description: "Reason for action"},
	"msg":     {Category: "event", Field: "message", Description: "Event message"},
	"cat":     {Category: "event", Field: "category", Description: "Event category"},

	// Time fields
	"rt":    {Category: "time", Field: "receipt_time", Description: "Receipt time"},
	"start": {Category: "time", Field: "start_time", Description: "Start time"},
	"end":   {Category: "time", Field: "end_time", Description: "End time"},

	// File fields
	"fname":    {Category: "file", Field: "name", Description: "File name"},
	"filePath": {Category: "file", Field: "path", Description: "File path"},
	"fsize":    {Category: "file", Field: "size", Description: "File size"},
	"fileHash": {Category: "file", Field: "hash", Description: "File hash"},

	// Request fields
	"request":        {Category: "request", Field: "url", Description: "Request URL"},
	"requestMethod":  {Category: "request", Field: "method", Description: "Request method"},
	"requestContext": {Category: "request", Field: "context", Description: "Request context"},

	// Device fields
	"dvc":     {Category: "device", Field: "ip", Description: "Device IP"},
	"dvchost": {Category: "device", Field: "hostname", Description: "Device hostname"},

	// Custom fields (cn1-cn3, cs1-cs6)
	"cn1": {Category: "custom", Field: "number1", Description: "Custom number 1"},
	"cn2": {Category: "custom", Field: "number2", Description: "Custom number 2"},
	"cn3": {Category: "custom", Field: "number3", Description: "Custom number 3"},
	"cs1": {Category: "custom", Field: "string1", Description: "Custom string 1"},
	"cs2": {Category: "custom", Field: "string2", Description: "Custom string 2"},
	"cs3": {Category: "custom", Field: "string3", Description: "Custom string 3"},
	"cs4": {Category: "custom", Field: "string4", Description: "Custom string 4"},
	"cs5": {Category: "custom", Field: "string5", Description: "Custom string 5"},
	"cs6": {Category: "custom", Field: "string6", Description: "Custom string 6"},

	// Label fields for custom fields
	"cn1Label": {Category: "custom", Field: "number1_label", Description: "Label for cn1"},
	"cn2Label": {Category: "custom", Field: "number2_label", Description: "Label for cn2"},
	"cn3Label": {Category: "custom", Field: "number3_label", Description: "Label for cn3"},
	"cs1Label": {Category: "custom", Field: "string1_label", Description: "Label for cs1"},
	"cs2Label": {Category: "custom", Field: "string2_label", Description: "Label for cs2"},
	"cs3Label": {Category: "custom", Field: "string3_label", Description: "Label for cs3"},
	"cs4Label": {Category: "custom", Field: "string4_label", Description: "Label for cs4"},
	"cs5Label": {Category: "custom", Field: "string5_label", Description: "Label for cs5"},
	"cs6Label": {Category: "custom", Field: "string6_label", Description: "Label for cs6"},
}

// GetExtensionInfo returns information about a CEF extension field.
func GetExtensionInfo(key string) (ExtensionInfo, bool) {
	info, ok := StandardExtensions[key]
	return info, ok
}

// IsSourceField returns true if the key is a source-related field.
func IsSourceField(key string) bool {
	info, ok := StandardExtensions[key]
	return ok && info.Category == "source"
}

// IsDestinationField returns true if the key is a destination-related field.
func IsDestinationField(key string) bool {
	info, ok := StandardExtensions[key]
	return ok && info.Category == "destination"
}

// IsTimeField returns true if the key is a time-related field.
func IsTimeField(key string) bool {
	info, ok := StandardExtensions[key]
	return ok && info.Category == "time"
}
