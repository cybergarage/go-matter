// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package tui

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func (s inputSchema) hint() string {
	hint := "true / false"
	if s.kind == signedKind {
		hint = fmt.Sprintf("signed [%d, %d]", s.min, s.max)
	}
	if s.kind == unsignedKind {
		hint = fmt.Sprintf("unsigned [%d, %d]", s.umin, s.umax)
	}
	if len(s.choices) > 0 {
		choices := make([]string, 0, len(s.choices))
		for name, n := range s.choices {
			choices = append(choices, fmt.Sprintf("%s=%d", name, n))
		}
		sort.Strings(choices)
		hint = fmt.Sprint(choices)
	}
	if s.nullable {
		hint += " / null"
	}
	return hint
}
func (u *UI) setForm() {
	if u.busy {
		return
	}
	backend, ok := u.backend.(setBackend)
	if !ok {
		return
	}
	d, ok := u.device()
	if !ok {
		return
	}
	p, ok := u.path()
	if !ok {
		return
	}
	schema, err := writableSchema(p)
	if err != nil {
		u.detail.SetText("SET disabled: " + err.Error())
		return
	}
	generation := u.generation
	field := tview.NewInputField().SetLabel("Value: ").SetFieldWidth(24)
	text := fmt.Sprintf("%s\nSET node %016X / %s\n%s\nAllowed: %s\nEnter sends once; Esc cancels. ACL checked by device, not by this DB.\nWrite ACK will be followed by a fresh GET; no automatic retry/rollback.", u.mode, d.ID, d.Name, pathLabel(p), schema.hint())
	if p.Cluster == 6 && p.Attribute == 0x4003 {
		text += "\nStartUpOnOff changes startup policy; current power uses separate Invoke."
	}
	note := tview.NewTextView().SetText(text).SetWrap(true)
	submit := func() {
		if u.busy {
			return
		}
		if generation != u.generation {
			u.closeDialog()
			u.detail.SetText("SET canceled: target selection changed; nothing sent.")
			return
		}
		value, e := schema.parse(field.GetText())
		if e != nil {
			note.SetText(text + "\nInvalid input: " + e.Error())
			return
		}
		u.closeDialog()
		u.start(false, 30*time.Second, func(ctx context.Context) (Result, error) { return backend.Set(ctx, d.ID, p, value) })
	}
	form := tview.NewForm().AddFormItem(field)
	if len(schema.choices) > 0 || schema.kind == boolKind || schema.nullable {
		choices := []string{}
		if schema.kind == boolKind {
			choices = []string{trueText, "false"}
		} else {
			for name := range schema.choices {
				choices = append(choices, name)
			}
			sort.Strings(choices)
		}
		if schema.nullable {
			choices = append(choices, "null")
		}
		form.AddDropDown("Select value: ", choices, -1, func(option string, _ int) { field.SetText(option) })
	}
	form.AddButton("Send", submit).AddButton("Cancel", u.closeDialog).SetFocus(0)
	noteHeight := 10
	if width, _ := u.screen.Size(); width < 95 {
		noteHeight = 13
	}
	box := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(note, noteHeight, 0, false).AddItem(form, 0, 1, true)
	box.SetBorder(true).SetTitle(" SET attribute — changes configuration ")
	u.dialog = true
	u.editorInput = field
	u.editorSubmit = submit
	u.pages.AddPage("dialog", box, true, true)
	u.app.SetFocus(field)
}
func (u *UI) editorKey(e *tcell.EventKey) bool {
	if u.dialog && u.editorSubmit != nil && u.app.GetFocus() == u.editorInput && e.Key() == tcell.KeyEnter {
		u.editorSubmit()
		return true
	}
	return false
}
