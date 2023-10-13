// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build nopwdcache

package gosnmp

func SetPwdCache() {
	PasswordCaching(false)
}
