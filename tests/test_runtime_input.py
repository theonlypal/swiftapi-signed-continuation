import os
import stat
from types import SimpleNamespace
import pytest
from swiftapi_native_service import runtime_input as R


def test_memory_descriptor_validates_before_read(monkeypatch):
    monkeypatch.setattr(R.platform,'system',lambda:'Linux')
    for name,value in {'F_SEAL_WRITE':8,'F_SEAL_GROW':4,'F_SEAL_SHRINK':2,'F_SEAL_SEAL':1,'F_GET_SEALS':1034}.items():
        monkeypatch.setattr(R.fcntl,name,value,raising=False)
    key='swiftapi_live_'+'1'*64
    info=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_nlink=0,st_size=len(key))
    monkeypatch.setattr(R.os,'fstat',lambda fd:info)
    monkeypatch.setattr(R.fcntl,'fcntl',lambda *args:15)
    monkeypatch.setattr(R.os,'pread',lambda fd,size,offset:key.encode())
    assert R.read_descriptor(5)==key
    info.st_mode|=0o044
    with pytest.raises(ValueError,match='owner-only'):R.read_descriptor(5)
    info.st_mode=stat.S_IFREG|0o600;info.st_nlink=1
    with pytest.raises(ValueError,match='anonymous'):R.read_descriptor(5)
    info.st_nlink=0
    monkeypatch.setattr(R.fcntl,'fcntl',lambda *args:0)
    with pytest.raises(ValueError,match='sealed'):R.read_descriptor(5)


@pytest.mark.parametrize('descriptor',[0,1,2,-1,True,'5'])
def test_private_descriptor_refuses_standard_channels(monkeypatch,descriptor):
    monkeypatch.setattr(R.platform,'system',lambda:'Linux')
    with pytest.raises(ValueError,match='nonstandard'):R.validate_descriptor(descriptor)


def test_private_descriptor_refuses_non_linux(monkeypatch):
    monkeypatch.setattr(R.platform,'system',lambda:'Darwin')
    with pytest.raises(ValueError,match='Linux'):R.validate_descriptor(5)


def test_runtime_signer_keeps_supplied_seed_out_of_files(tmp_path):
    from swiftapi_native_service.core import RuntimeSigner
    from nacl.signing import SigningKey
    import base64
    seed=bytes(range(32))
    signer=RuntimeSigner(tmp_path/'runtime',seed=seed)
    assert signer.public==base64.b64encode(bytes(SigningKey(seed).verify_key)).decode()
    assert not (tmp_path/'runtime/runtime-signing.seed').exists()
    assert (tmp_path/'runtime/runtime-public.json').is_file()


def test_signing_descriptor_has_exact_length(monkeypatch):
    monkeypatch.setattr(R,'validate_descriptor',lambda fd:32)
    monkeypatch.setattr(R.os,'pread',lambda fd,size,offset:b'x'*size)
    assert R.read_signing_seed(5)==b'x'*32
    monkeypatch.setattr(R,'validate_descriptor',lambda fd:31)
    with pytest.raises(ValueError,match='exactly 32'):R.read_signing_seed(5)


def test_registered_signing_identity_is_checked_before_execution(monkeypatch):
    from swiftapi_native_service.experiment import validated_runtime_seed
    from nacl.signing import SigningKey
    import base64
    seed=bytes(range(32))
    public=base64.b64encode(bytes(SigningKey(seed).verify_key)).decode('ascii')
    config={'purpose':'PREREGISTERED_STUDY','runtime_public_key':public}
    monkeypatch.setattr(R,'read_signing_seed',lambda fd:seed)
    assert validated_runtime_seed(config,5)==seed
    with pytest.raises(ValueError,match='requires its private descriptor'):
        validated_runtime_seed(config,None)
    with pytest.raises(ValueError,match='does not match'):
        validated_runtime_seed(dict(config,runtime_public_key='different'),5)
    with pytest.raises(ValueError,match='registered public key'):
        validated_runtime_seed(dict(config,purpose='DEVELOPMENT_SMOKE'),5)
    assert validated_runtime_seed({'purpose':'DEVELOPMENT_SMOKE'},None) is None
    assert validated_runtime_seed(dict(config,purpose='DEVELOPMENT_SMOKE',authority='LOCAL_TEST_DOUBLE'),5)==seed
    with pytest.raises(ValueError,match='registered public key'):
        validated_runtime_seed(dict(config,purpose='DEVELOPMENT_SMOKE',authority='LIVE_SWIFTAPI'),5)


def test_smoke_descriptor_rejects_non_dummy_before_output(monkeypatch,tmp_path):
    from swiftapi_native_service import experiment as E,mac_ledger
    monkeypatch.setattr(E,'validate_config',lambda *args:None)
    monkeypatch.setattr(mac_ledger,'read_before',lambda *args:None)
    monkeypatch.setattr(R,'validate_descriptor',lambda fd:77)
    monkeypatch.setattr(R,'read_descriptor',lambda fd:'swiftapi_live_'+'1'*64)
    config={'purpose':'DEVELOPMENT_SMOKE','authority':'LOCAL_TEST_DOUBLE'}
    with pytest.raises(ValueError,match='public dummy'):
        E.run(config,None,tmp_path/'out',None,None,None,key_fd=7)
    assert not (tmp_path/'out').exists()


def test_smoke_key_file_remains_prohibited(tmp_path):
    from swiftapi_native_service import experiment as E
    with pytest.raises(ValueError,match='No SwiftAPI key'):
        E.run({'purpose':'DEVELOPMENT_SMOKE'},None,tmp_path/'out',None,None,None,key_file=tmp_path/'key')


@pytest.mark.parametrize('descriptor',[None,7])
def test_signing_input_refusal_precedes_approval_and_output(monkeypatch,tmp_path,descriptor):
    from swiftapi_native_service import experiment as E,mac_ledger
    monkeypatch.setattr(E,'validate_config',lambda *args:None)
    monkeypatch.setattr(mac_ledger,'read_before',lambda *args:None)
    monkeypatch.setattr(R,'read_signing_seed',lambda fd:bytes(range(32)))
    monkeypatch.setattr(E,'consume_approval',lambda *args:pytest.fail('No approval is consumed'))
    config={'purpose':'PREREGISTERED_STUDY','authority':'LIVE_SWIFTAPI',
            'runtime_public_key':'different'}
    out=tmp_path/'output'
    with pytest.raises(ValueError,match='private descriptor|does not match'):
        E.run(config,None,out,None,None,None,key_file=tmp_path/'no-key',runtime_seed_fd=descriptor)
    assert not out.exists()
