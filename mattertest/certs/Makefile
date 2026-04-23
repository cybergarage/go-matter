# Copyright (C) 2026 The go-matter Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.PHONY: certgen clean

all: certgen

ADMIN_NODE_ID_HEX ?= 0000000000000001
FABRIC_ID_HEX ?= 0000000000000002
DAYS ?= 36500

ROOT_KEY = admin-root-key.pem
ROOT_CERT = admin-root-cert.pem
ADMIN_KEY = admin-private-key.pem
ADMIN_NOC = admin-noc.pem
TEMP_FILES = admin-noc.cnf admin-noc.csr admin-noc.ext admin-root-cert.srl

# Matter 1.2 Core Spec 4.13.2 "Certificate Authenticated Session Establishment (CASE)"
# AdministratorConfig requires the administrator RCAC, NOC, and private key.
# The administrator NOC subject carries Matter Node ID and Fabric ID RDNs:
#   1.3.6.1.4.1.37244.1.1: Matter Node ID
#   1.3.6.1.4.1.37244.1.5: Matter Fabric ID
certgen: clean
	ADMIN_NODE_ID_HEX=$(ADMIN_NODE_ID_HEX) FABRIC_ID_HEX=$(FABRIC_ID_HEX) DAYS=$(DAYS) go run ./certgen.go

clean:
	rm -f $(ROOT_KEY) $(ROOT_CERT) $(ADMIN_KEY) $(ADMIN_NOC) $(TEMP_FILES)
