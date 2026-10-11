// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

// Package datamodel provides a pinned, partial SDK ZAP metadata catalog.
// Definitions describe schema, never a device's support, access rights or protocol implementation.
package datamodel

import (
	"slices"

	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// XMLAttribute preserves a source attribute, including its namespace.
type XMLAttribute struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Value     string `json:"value"`
}

// Element preserves audited XML metadata and ordered child trees. No conformance
// expression, privilege or constraint is evaluated by this initial catalog.
type Element struct {
	Name       string         `json:"name"`
	Namespace  string         `json:"namespace,omitempty"`
	Attributes []XMLAttribute `json:"attributes,omitempty"`
	Text       string         `json:"text,omitempty"`
	Children   []Element      `json:"children,omitempty"`
}

func (e Element) Property(name string) string {
	for _, a := range e.Attributes {
		if a.Name == name && a.Namespace == "" {
			return a.Value
		}
	}
	return ""
}
func (e Element) Child(name string) (Element, bool) {
	for _, child := range e.Children {
		if child.Name == name {
			return child, true
		}
	}
	return Element{}, false
}

// NamedChildren returns source-ordered child metadata (e.g. access, arg or features).
func (e Element) NamedChildren(name string) []Element {
	var out []Element
	for _, child := range e.Children {
		if child.Name == name {
			out = append(out, child)
		}
	}
	return out
}

type Source struct {
	File    string `json:"file"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	License string `json:"license"`
}
type Provenance struct {
	SDKTag           string   `json:"sdkTag"`
	SourceSHA        string   `json:"sourceSha"`
	GeneratorVersion string   `json:"generatorVersion"`
	Inputs           []Source `json:"inputs"`
}
type Document struct {
	File string  `json:"file"`
	Root Element `json:"root"`
}

// SchemaVersion identifies the language-independent JSON consumer contract.
const SchemaVersion = 1

// Catalog is caller-owned metadata, loaded independently each time. Mutating it
// cannot alter another consumer's catalog. Unknown numeric IDs return found=false.
type Catalog struct {
	SchemaVersion int              `json:"schemaVersion"`
	Provenance    Provenance       `json:"provenance"`
	Documents     []Document       `json:"documents"`
	Clusters      []Cluster        `json:"clusters"`
	DeviceTypes   []DeviceType     `json:"deviceTypes"`
	Types         []TypeDefinition `json:"types"`
	Globals       []Attribute      `json:"globals"`
}
type Cluster struct {
	ID         im.ClusterID `json:"id"`
	Name       string       `json:"name"`
	Revision   uint16       `json:"revision"`
	Source     string       `json:"source"`
	Definition Element      `json:"definition"`
	Attributes []Attribute  `json:"attributes"`
	Commands   []Command    `json:"commands"`
}
type Attribute struct {
	ID   im.AttributeID `json:"id"`
	Name string         `json:"name"`
	Type string         `json:"type"`
	// Writable/Nullable reflect explicit ZAP properties; Definition preserves access/feature conditions.
	Writable   bool    `json:"writable"`
	Nullable   bool    `json:"nullable"`
	Definition Element `json:"definition"`
}
type Command struct {
	ID   im.CommandID `json:"id"`
	Name string       `json:"name"`
	// Source is the SDK direction (client request/server response), not proof of an accepted command.
	Source     string  `json:"source"`
	Timed      bool    `json:"timed"`
	Definition Element `json:"definition"`
}

// DeviceType is an application device profile, distinct from discovery DeviceType.
// Requirements reference SDK cluster names; unloaded clusters stay unresolved.
type DeviceType struct {
	ID             uint32  `json:"id"`
	Name           string  `json:"name"`
	Revision       uint16  `json:"revision"`
	VendorSpecific bool    `json:"vendorSpecific"`
	Definition     Element `json:"definition"`
}
type TypeDefinition struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Source string `json:"source"`
	// Clusters is the applicability scope; empty means global. SDK atomic IDs are not Matter TLV types.
	Clusters   []im.ClusterID `json:"clusters,omitempty"`
	Definition Element        `json:"definition"`
}

func (c *Catalog) Cluster(id im.ClusterID) (Cluster, bool) {
	for _, v := range c.Clusters {
		if v.ID == id {
			return v, true
		}
	}
	return Cluster{}, false
}
func (c *Catalog) DeviceType(id uint32) (DeviceType, bool) {
	for _, v := range c.DeviceTypes {
		if v.ID == id {
			return v, true
		}
	}
	return DeviceType{}, false
}
func (c *Catalog) Type(name string, cluster im.ClusterID) (TypeDefinition, bool) {
	var global TypeDefinition
	var found bool
	for _, v := range c.Types {
		if v.Name != name {
			continue
		}
		if slices.Contains(v.Clusters, cluster) {
			return v, true
		}
		if len(v.Clusters) == 0 {
			global = v
			found = true
		}
	}
	return global, found
}
func (c Cluster) Attribute(id im.AttributeID) (Attribute, bool) {
	for _, v := range c.Attributes {
		if v.ID == id {
			return v, true
		}
	}
	return Attribute{}, false
}
func (c Cluster) Command(id im.CommandID, source string) (Command, bool) {
	for _, v := range c.Commands {
		if v.ID == id && v.Source == source {
			return v, true
		}
	}
	return Command{}, false
}

// GlobalAttribute returns global metadata without claiming a device-reported value.
func (c *Catalog) GlobalAttribute(id im.AttributeID) (Attribute, bool) {
	for _, v := range c.Globals {
		if v.ID == id {
			return v, true
		}
	}
	return Attribute{}, false
}

// Attribute prefers a cluster definition before falling back to a global attribute.
// It does not imply that the device advertises or permits access to the attribute.
func (c *Catalog) Attribute(id im.AttributeID, clusterID im.ClusterID) (Attribute, bool) {
	if cluster, ok := c.Cluster(clusterID); ok {
		if attribute, found := cluster.Attribute(id); found {
			return attribute, true
		}
	}
	return c.GlobalAttribute(id)
}
