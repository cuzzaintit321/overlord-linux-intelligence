import os,tempfile
from fastapi.testclient import TestClient

def test_features():
    with tempfile.TemporaryDirectory() as d:
        os.environ['OVERLORD_DB']=d+'/test.db'
        from app import main
        main.DB=main.Path(os.environ['OVERLORD_DB'])
        main.TOKEN='test-secret'
        with TestClient(main.app) as c:
            assert c.get('/api/status').status_code==401
            h={'x-overlord-token':'test-secret'}
            assert c.get('/api/status',headers=h).status_code==200
            assert isinstance(c.get('/api/processes',headers=h).json(),list)
            assert c.get('/api/diagnostics',headers=h).status_code==200
            assert c.post('/api/rules',headers=h,json={'name':'Test threshold','metric':'cpu','operator':'>','threshold':80}).status_code==200
            assert len(c.get('/api/rules',headers=h).json())>=4
            assert c.post('/api/snapshots',headers=h).status_code==200
            assert len(c.get('/api/snapshots',headers=h).json())==1
            assert 'events' in c.get('/api/export',headers=h).json()
            assert c.get('/').status_code==200
