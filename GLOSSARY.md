# Glossary

SNMP terms (RFCs 1157, 3411-3418) whose Go names in gosnmp differ. The Go names predate this vocabulary and stay because they are public API.

**Message**:
One complete SNMP unit as sent over the network: version, community or v3 header and security parameters, and a PDU.
_Note_: the Go type is `SnmpPacket`. In the code, "packet" means both a message and the raw bytes it is decoded from.

**Variable binding**:
One object name (an OID) paired with a typed value, as carried in a PDU's list of bindings; also called a varbind.
_Note_: the Go type is `SnmpPDU`, a name from the 2012 rewrite to a hand-written BER parser. The `VarBind` type from the original `encoding/asn1` decoder is still exported but unused.

**Notification**:
A message an engine sends unprompted: a trap, which is not acknowledged, or an inform, which the receiver answers.
_Note_: the API says "trap" for both; an inform is an `SnmpTrap` with `IsInform` set, and `TrapListener` receives both.

**Agent**:
The SNMP entity that answers requests and sends notifications.
_Note_: `GoSNMP.Target` holds the agent's address. When gosnmp sends a trap it acts as an agent, which is why the v1 trap field `AgentAddress` names the sender.

**Security level**:
How a v3 message is protected: noAuthNoPriv, authNoPriv or authPriv.
_Note_: the API stores it in `MsgFlags` (`SnmpV3MsgFlags`), together with the unrelated Reportable flag.

**Authoritative engine**:
The engine whose engine ID, boots and time a v3 message's keys and time window use: the receiver of messages that expect a response (requests, informs) and the sender of those that don't (responses, reports, traps).
_Note_: the `Authoritative*` fields of `UsmSecurityParameters` describe this engine, whichever side it is.

**Engine ID**:
The unique identifier of an SNMP engine, 5 to 32 octets.
_Note_: `AuthoritativeEngineID` holds the raw octets as a Go string, not hex text, so `"0x8000..."` as written in net-snmp config is wrong (#344, #469).

**Community**:
The clear-text string a v1/v2c message carries to name the community it belongs to; the receiver uses it as a trivial authentication check.
_Note_: `TrapListener` does not check the community of received notifications (#281).
