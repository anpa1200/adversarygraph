from app.services.ioc_extractor import extract_iocs_from_text, is_public_domain


def test_code_symbols_and_filenames_do_not_become_domain_iocs():
    text = ('The dropper calls fs.rename and fs.unlink, fs.copyFileSync, os.arch, os.platform, '
            'objShell.Run and WScript.Shell. It executes setup.js, ld.py, 6202033.vbs and '
            'stepsecurity-dev-machine-guard.sh. C2 callback uses sfrclak.com:8000.')
    domains = {item.value for item in extract_iocs_from_text(text) if item.indicator_type == 'domain'}
    assert domains == {'sfrclak.com'}


def test_real_uncommon_tlds_are_retained_and_reserved_names_are_not_public():
    domains = {item.value for item in extract_iocs_from_text('Observed attacker.xyz, payload.guru and internal.lab.test.')
               if item.indicator_type == 'domain'}
    assert {'attacker.xyz', 'payload.guru', 'internal.lab.test'} <= domains
    assert is_public_domain('attacker.xyz')
    assert not is_public_domain('internal.lab.test')
    assert not is_public_domain('fs.rename')


def test_unspecified_address_is_not_an_actionable_external_indicator():
    ips = {item.value for item in extract_iocs_from_text('Listen on 0.0.0.0; C2 is 142.11.206.73.')
           if item.indicator_type == 'ipv4'}
    assert ips == {'142.11.206.73'}
