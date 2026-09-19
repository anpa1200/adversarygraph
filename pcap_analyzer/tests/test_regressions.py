from types import SimpleNamespace
from pathlib import Path
import pytest
import pcap_analyzer.app as analyzer


def event(frame, src='10.0.0.5', dst='10.0.0.2', **fields):
    return {'frame_number': frame, 'src_ip': src, 'dst_ip': dst, 'tcp_stream': 1,
            'timestamp_epoch': str(frame * 30), 'fields': fields}


def test_keepalive_responses_use_frame_links_not_last_request():
    first = event(1, **{'http.request.uri': '/first.exe'})
    last = event(3, **{'http.request.uri': '/callback'})
    reply = event(2, src='10.0.0.2', dst='10.0.0.5', **{'http.request_in': '1'})
    assert analyzer._paired_request(reply, {1: first, 3: last}) == first
    reply['fields']['http.request_in'] = '3'
    assert analyzer._paired_request(reply, {1: first, 3: last}) is None


@pytest.mark.parametrize('change', ['missing', 'wrong_stream', 'wrong_direction'])
def test_response_pairing_fails_closed(change):
    request = event(1)
    reply = event(2, src='10.0.0.2', dst='10.0.0.5', **{'http.request_in': '1'})
    if change == 'missing': reply['fields'] = {}
    if change == 'wrong_stream': reply['tcp_stream'] = 2
    if change == 'wrong_direction': reply['src_ip'] = '10.0.0.3'
    assert analyzer._paired_request(reply, {1: request}) is None


def test_directory_subject_is_not_server_or_unproven_client_owner():
    directory = event(2, src='10.0.0.2', dst='10.0.0.5', **{
        'samr.samr_UserInfo21.account_name': 'alice', 'samr.samr_UserInfo21.full_name': 'Alice Example'})
    only = analyzer._build_identities('a'*64, {'identity': [directory]})
    assert all(not i['ip_addresses'] for i in only)
    request = event(1, **{'kerberos.CNameString': 'alice', 'kerberos.msg_type': '10'})
    combined = analyzer._build_identities('a'*64, {'identity': [directory, request]})
    assert all(i['ip_addresses'] == ['10.0.0.5'] for i in combined)


def test_netbios_query_does_not_name_requester():
    query = event(1, **{'nbns.name': 'OTHERHOST<00>', 'nbns.flags.opcode': '0'})
    assert analyzer._build_identities('a'*64, {'identity': [query]}) == []
    query['fields']['nbns.flags.opcode'] = '5'
    identities = analyzer._build_identities('a'*64, {'identity': [query]})
    assert identities[0]['value'] == 'OTHERHOST'
    assert identities[0]['ip_addresses'] == ['10.0.0.5']


def test_generic_binary_and_empty_response_not_executable():
    for content_type, length in [('application/octet-stream', '9'), ('application/x-msdownload', '0')]:
        reply = event(2, **{'http.content_type': content_type, 'http.content_length': length})
        assert not analyzer._build_findings('a'*64, {'http_response': [reply]})


@pytest.mark.parametrize('boolean', ['1', 'True', 'true'])
def test_netbios_group_is_not_a_hostname(boolean):
    query = event(1, **{'nbns.name': 'DOMAIN<00>', 'nbns.flags.opcode': '5', 'nbns.nb_flags.group': boolean})
    identity = analyzer._build_identities('a'*64, {'identity': [query]})[0]
    assert identity['type'] == 'netbios-group'
    assert identity['ip_addresses'] == []


def test_repeated_posts_do_not_assert_exfiltration():
    findings = [{'rule_id': rule} for rule in ('repeated-http-posts', 'large-http-post', 'high-volume-http-posts', 'browser-fingerprint-upload')]
    assert analyzer._attack_candidates(findings) == []


def test_payloads_survive_callback_metadata_flood(tmp_path, monkeypatch):
    directory = tmp_path / 'http-objects'
    directory.mkdir()
    for n in range(510):
        (directory / f'000-callback-{n}').write_bytes(b'OK\r\n')
    for n in range(6):
        (directory / f'zzz-payload-{n}.ps1').write_text(f'Invoke-WebRequest https://example.test/{n}')
    monkeypatch.setattr(analyzer.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=0))
    inventory = {}
    artifacts, warnings = analyzer._export_http_objects(tmp_path, Path('unused'), 'a'*64, inventory=inventory)
    assert len(artifacts) == 7
    assert sum(a['occurrences'] for a in artifacts) == 516
    assert inventory['complete'] and not warnings
    assert len([a for a in artifacts if a['static_features']['content_kind'] == 'script-like-text']) == 6


def test_truncated_inventory_is_explicit(tmp_path, monkeypatch):
    directory = tmp_path / 'http-objects'
    directory.mkdir()
    for n in range(3): (directory / str(n)).write_text(str(n))
    monkeypatch.setattr(analyzer.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=0))
    monkeypatch.setattr(analyzer, 'MAX_EXPORTED_OBJECTS', 1)
    monkeypatch.setattr(analyzer, 'MAX_OBJECT_HASH_INDEX', 0)
    inventory = {}
    artifacts, warnings = analyzer._export_http_objects(tmp_path, Path('unused'), 'a'*64, inventory=inventory)
    assert len(artifacts) == 1 and warnings
    assert inventory['omitted_unique_hashes'] == 2 and not inventory['complete']


def test_compact_index_preserves_hashes_beyond_rich_metadata_cap(tmp_path, monkeypatch):
    directory = tmp_path / 'http-objects'
    directory.mkdir()
    for n in range(3): (directory / str(n)).write_text(str(n))
    monkeypatch.setattr(analyzer.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=0))
    monkeypatch.setattr(analyzer, 'MAX_EXPORTED_OBJECTS', 1)
    inventory = {}
    artifacts, warnings = analyzer._export_http_objects(tmp_path, Path('unused'), 'a'*64, inventory=inventory)
    assert len(artifacts) == 1 and not warnings
    assert len(inventory['compact_hash_index']) == 2
    assert inventory['complete'] and inventory['returned_unique_hashes'] == 3


def test_literal_tool_label_is_data_not_hardcoded_family():
    message = b'ping|ExampleTool|ABCD1234|HOST-ONE|alice|Windows'
    raw = event(9, **{'tcp.payload':message.hex()})
    raw['dst_port'] = 9999
    finding = analyzer._unclassified_findings('a'*64, {'unclassified_tcp':[raw]}, [])[0]
    assert finding['metrics']['software_label'] == 'ExampleTool'
    assert 'not authenticated' in finding['explanation']
    assert analyzer._attack_candidates([finding]) == []


def test_null_ntlm_placeholders_are_not_identities():
    raw = event(1, **{'ntlmssp.auth.username':'NULL','ntlmssp.auth.domain':'NULL'})
    assert analyzer._build_identities('a'*64, {'identity':[raw]}) == []


def test_regular_tls_is_candidate_not_attribution():
    events = [event(1+i*3+j, **{'tls.handshake.extensions_server_name': f'telemetry{j}.example', 'tls.handshake.ja3': 'same'})
              for i in range(5) for j in range(3)]
    findings = analyzer._context_findings('a'*64, {'tls_client_hello': events})
    assert findings[0]['rule_id'] == 'multi-host-tls-cadence'
    assert 'legitimate' in findings[0]['explanation']
    assert not analyzer._attack_candidates(findings)


def test_implementation_digest_in_manifest(monkeypatch):
    monkeypatch.setattr(analyzer, '_MANIFEST', None)
    monkeypatch.setattr(analyzer, '_supported_fields', lambda: {'frame.number'})
    monkeypatch.setattr(analyzer, '_tool_version', lambda _: 'test')
    assert len(analyzer.analyzer_manifest()['implementation_sha256']) == 64
