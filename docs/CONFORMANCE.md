# RFC 1928 / RFC 1929 conformance matrix

Baseline built on 2026-10-14 by the `rfc-conformance` checker (roadmap M1.5): requirements read from
rfc-editor.org, code located in `proxy.py`, tests found in `tests/`, and unclear items probed with raw bytes against
a locally started instance (plain and `--auth`). Scope: a CONNECT-only server; UDP, fragmentation and `BIND`
requirements are out of scope (see the end of the matrix).

Status: **conforms** | **documented deviation** | **UNDOCUMENTED DEVIATION** | **untested**. "Documented" means the
README section "SOCKS5 behaviour" says so. Line numbers are those of `proxy.py` at commit 6885e2a, when the matrix was
made (later commits moved them; the function names still hold); test names
were checked to exist (all 57 cited names were found by grep). The "Test" column says a test of that name exists and
appears to pin the requirement; the checker did not read every test body.

Result: no undocumented wire deviation. The 4 documentation gaps found are closed in the README (roadmap M1.7,
2026-10-15). The baseline also listed 2 requirements as untested; a later review (M0.7) showed both were already pinned
by existing tests, and M1.7 added stricter ones (see Findings).

## RFC 1928, section 3 (method selection)

| Requirement | proxy.py | Test | Status |
|---|---|---|---|
| Greeting is VER=05, NMETHODS, METHODS (1..255); the server reads exactly that many bytes | `negotiate` 115-118 | protocol `test_all_255_offered_methods_are_consumed`, `test_message_split_at_every_possible_point`, `test_message_delivered_one_byte_at_a_time`; integration `test_handshake_dribbled_one_byte_at_a_time_works` | conforms |
| Server selects one METHOD and replies `05 METHOD` | `negotiate` 119, 124-125 | protocol `test_no_authentication_is_selected_and_nothing_else_consumed`, `test_username_password_is_chosen_even_if_no_auth_is_offered_first` | conforms |
| No acceptable method: server sends `05 FF`, then the connection is closed | `negotiate` 120-123; `_serve` 453-458 | protocol `test_only_unacceptable_methods_get_the_no_acceptable_reply`, `test_zero_methods_offered_gets_the_no_acceptable_reply`; integration `test_no_acceptable_method_gets_05_ff`, `test_no_authentication_offer_is_refused_by_an_authenticating_proxy` | conforms |
| "MUST support GSSAPI" (method 01) | not implemented | n/a | documented deviation |
| "SHOULD support USERNAME/PASSWORD" (method 02) | `negotiate` 119, 126-127; `_authenticate` 130-143 | integration AuthTests (`test_correct_credentials_allow_connect`, ...) | conforms (only with `--auth`; the default is no authentication, documented) |
| Wrong VER in the greeting (not specified by the RFC) | `negotiate` 116-117: dropped, no reply | protocol `test_wrong_greeting_version_is_dropped_silently`; integration `test_non_socks5_greeting_is_dropped_without_a_reply` | documented (README "Version" row) |

## RFC 1929 (username/password)

| Requirement | proxy.py | Test | Status |
|---|---|---|---|
| Request is VER=01, ULEN, UNAME, PLEN, PASSWD; exact-length reads | `_authenticate` 133-138 | protocol `test_maximum_length_credentials_work`, `test_credentials_may_contain_arbitrary_bytes`, `test_every_truncation_of_the_authentication_exchange_is_incomplete`; fuzz `test_only_the_exact_credentials_are_accepted`, `test_mutated_authentication_messages_never_raise_anything_unexpected` | conforms |
| Response is `01 STATUS`; 00 = success | `_authenticate` 142-143 | protocol `test_correct_credentials_are_accepted` | conforms |
| Wrong credentials give a non-zero STATUS | `_authenticate` 140-141 (`01 01`) | protocol `test_wrong_credentials_get_failure_status`; integration `test_wrong_credentials_are_rejected_and_nothing_is_connected` | conforms (documented: README "Auth failure" row) |
| On failure the server MUST close the connection | `ProtocolError` reply, then `_serve` 453-458 and 488-490 | same tests | conforms (probed: EOF follows `01 01`) |
| Sub-negotiation VER other than 01 is refused | `_authenticate` 134-135 (`01 01`, close) | protocol `test_wrong_subnegotiation_version_is_rejected_even_with_right_credentials` | conforms (documented: README "Auth failure" row) |
| Zero-length UNAME or PASSWD (the RFC says 1..255) | `_authenticate` 133-141: read, compares unequal to the non-empty configured credentials, answer `01 01` | integration `test_wrong_credentials_are_rejected_and_nothing_is_connected` (empty credentials), `test_zero_length_username_or_password_on_the_wire_gets_01_01_and_a_close`; protocol empty-field tests | conforms (documented: README "Auth failure" row) |
| A request cannot skip authentication | `negotiate` 126-127 | integration `test_authentication_cannot_be_skipped_by_sending_a_request`; cli `test_request_without_authenticating_is_refused` | conforms |
| Password is sent in clear text (RFC 1929 section 3) | n/a | n/a | documented (README: auth is opt-in, use SSH or loopback) |

## RFC 1928, sections 4 and 5 (requests and addressing)

| Requirement | proxy.py | Test | Status |
|---|---|---|---|
| Request layout VER CMD RSV ATYP DST.ADDR DST.PORT, port big-endian | `read_request` 155-169 | protocol `test_ipv4_request`, `test_port_is_decoded_big_endian`, `test_ipv6_request`, `test_domain_request`, `test_full_handshake_for_each_address_type`; fuzz `test_valid_requests_parse_back_exactly_and_leave_trailing_bytes_unread` | conforms |
| ATYP 01 (4 octets), 03 (length byte, no NUL), 04 (16 octets) | `read_request` 159-165 | protocol `test_domain_length_extremes`, `test_utf8_domain_is_decoded_to_text`, `test_ipv6_request_is_canonicalised` | conforms |
| CMD CONNECT (01) | `read_request` 171, `connect_upstream` 242-276 | integration ConnectTests | conforms |
| CMD BIND (02) and UDP ASSOCIATE (03): reply 07 | `read_request` 171-173 | protocol `test_unsupported_commands_get_reply_07_after_the_whole_request_is_read`; integration `test_unsupported_commands_get_rep_07_for_every_address_type`; fuzz `test_a_command_other_than_connect_is_refused_whatever_the_address` | documented deviation (CONNECT only) |
| RSV in a request is X'00' (the server is not required to check it) | `read_request` 155 (ignored) | protocol `test_reserved_byte_is_ignored` | conforms (tolerated; documented: README "Reserved byte" row) |
| Request VER other than 05 | `read_request` 156-158: `05 01 00 01 0.0.0.0 0`, close | protocol `test_wrong_request_version_gets_general_failure`; integration `test_wrong_request_version_gets_general_failure` | documented (README REP 01 row) |
| Unknown ATYP: reply 08 | `read_request` 166-168 | protocol `test_unsupported_address_types_get_reply_08`, `test_unsupported_address_type_is_answered_without_waiting_for_more_bytes`; integration `test_unsupported_address_types_get_rep_08` | conforms |
| A domain name is length-prefixed, "no terminating NUL" | `read_request` 163-165, 174-183 (control characters and NUL get REP 04) | protocol `test_control_characters_in_a_domain_name_are_rejected`, `test_empty_domain_gets_host_unreachable`, `test_undecodable_domain_gets_host_unreachable`; fuzz `test_unusable_domain_names_get_host_unreachable` | conforms (the extra rejection is documented) |

## RFC 1928, section 6 (replies)

| Requirement | proxy.py | Test | Status |
|---|---|---|---|
| Reply layout VER REP RSV(00) ATYP BND.ADDR BND.PORT | `encode_reply` 97-104 | protocol `test_ipv4_success_reply_layout`, `test_ipv6_reply_layout`, `test_every_rep_code_lands_in_byte_one_of_a_ten_byte_zero_address_reply`, `test_port_is_two_bytes_big_endian_at_the_bounds`; fuzz `test_replies_decode_back_to_what_was_encoded` | conforms |
| REP 00..08 meanings | `_ERRNO_TO_REP` 188-200; `rep_for_exception` 208-227 (on Windows also `_WINERROR_TO_REP`, since 1.1.0) | protocol ConstantsTests `test_reply_codes_match_rfc_1928`, ReplyCodeMappingTests; integration `test_connect_errors_map_to_reply_codes`, `test_connection_refused_is_rep_05`, `test_connect_timeout_is_rep_06`, `test_unresolvable_name_is_rep_04` | conforms (mapping documented) |
| BND.ADDR/BND.PORT carry the proxy's outgoing socket on success | `_serve` 473-475 | integration `test_ipv4_connect_reports_the_outgoing_socket_and_relays_data`, `test_ipv6_connect_reports_an_ipv6_bound_address` | conforms |
| REP not 00: the server MUST terminate the TCP connection shortly after the reply (no more than 10 s) | `_serve` 453-460, 465-471, then `finally` 488-490 | integration: `read_all` (fails unless the proxy closes within 5 s) after every error reply; `test_every_error_reply_is_followed_by_eof_within_the_rfc_limit` (every error path, EOF within 2 s) | conforms |
| Error reply uses ATYP 01 with 0.0.0.0:0 | `encode_reply` defaults | `test_every_rep_code_lands_in_byte_one_of_a_ten_byte_zero_address_reply` | conforms (documented) |
| The server MUST encapsulate data as the authentication method requires | only methods 00 and 02, which have no encapsulation | n/a | conforms (not applicable) |

## Out of scope for a CONNECT-only server

UDP ASSOCIATE, the UDP header, FRAG, the reassembly timer, source-address filtering and the `BIND` second reply:
the commands are refused with REP 07. Documented deviation.

## Findings

No undocumented wire deviation. Probe results (hex; "g" = `05 01 00`; "tp" = a loopback target port):

| In | Out |
|---|---|
| g, CONNECT 127.0.0.1:tp | `0500`, then `05 00 00 01 7f000001 <port>`; connection stays open |
| g, request with RSV=55 | success reply, as above |
| `05 00` (NMETHODS=0) | `05ff`, EOF |
| g, BIND / UDP ASSOCIATE | `0500`, `05 07 00 01 00000000 0000`, EOF |
| g, ATYP 09 (also with 500 trailing bytes) | `05 08 00 01 00000000 0000`, EOF |
| g, BIND with ATYP 07 | `05 08 ...`: the address type is checked before the command |
| `04 01 <port>` (SOCKS4) | nothing, EOF |
| `--auth`: wrong password / sub-VER 02 / ULEN=0 PLEN=0 | `0502`, `0101`, EOF |
| `--auth`: offers `00` only | `05ff`, EOF |

**Documentation gaps** (code conforms, the README did not say so; items 1 to 3 are documented since 2026-10-15):

1. RSV in a request is ignored (success reply for `05 01 55 01 ...`).
2. The RFC 1929 failure reply is `01 01` and the connection is closed afterwards; a wrong sub-negotiation version gets the same.
3. Zero-length credentials on the wire (`01 00 00`) get `01 01` and EOF.
4. The README said "The command is checked first, so BIND/UDP ASSOCIATE always get REP 07, whatever the address". That is
   true for ATYP 01/03/04 but not for an unknown ATYP, which gets REP 08 first (verified by the lead; the `read_request`
   docstring had it right). Fixed in the README.

**Untested** (as the baseline claimed): zero-length UNAME/PASSWD on the wire; the EOF after an error reply (the RFC's
10 s rule). Correction (M0.7 review, 2026-10-15): both were already pinned. The integration test
`test_wrong_credentials_are_rejected_and_nothing_is_connected` sends `01 00 00`, and the `read_all` helper used after
every error reply fails unless the proxy closes within 5 s; mutants that keep the connection open or accept empty
credentials fail 29 and 3 tests. M1.7 added the one-sided zero-length cases and a 2 s bound for every error path.

## Not checked

Scoped IPv6 (`fe80::1%eth0`) beyond the unit tests; a large payload after an error reply (a TCP RST could pre-empt the
reply; none seen with 500 bytes); real clients (curl, browsers, ssh); Python 3.6; the test column was matched by name,
and the checker did not run the suite.
