"""Nombres e identidades reconocidas por el usuario; sin guardar tráfico.

La base se crea sólo al guardar explícitamente un dispositivo. Las lecturas
durante la captura usan memoria; las escrituras SQLite son transaccionales.
"""
import copy
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
import threading
import time


def normalize_mac(value):
    value = str(value).strip().lower().replace('-', ':')
    if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', value):
        return ''
    if int(value[:2], 16) & 1 or value == '00:00:00:00:00:00':
        return ''
    return value


class DeviceRegistry:
    MAX_RECORDS = 2048
    MAX_AUDITS = 16

    def __init__(self, path=None):
        self.path = Path(path) if path is not None else None
        self.lock = threading.RLock()
        self._records = {}
        self._audits = {}
        self.error = None
        if self.path and self.path.exists():
            try:
                with self._connection() as conn:
                    tables = {
                        r[0]
                        for r in conn.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        ).fetchall()
                    }
                    if 'devices' in tables:
                        rows = conn.execute(
                            'SELECT network, identity, ip, mac, name, notes, recognized, updated FROM devices LIMIT ?',
                            (self.MAX_RECORDS + 1,),
                        ).fetchall()
                        if len(rows) > self.MAX_RECORDS:
                            raise ValueError('La base de dispositivos supera el límite de registros.')
                        for row in rows:
                            record = dict(row)
                            self._records[(record['network'], record['identity'])] = record
                    if 'audits' in tables:
                        audit_rows = conn.execute(
                            'SELECT ip, payload FROM audits ORDER BY finished ASC LIMIT ?',
                            (self.MAX_AUDITS + 1,),
                        ).fetchall()
                        for row in audit_rows[-self.MAX_AUDITS:]:
                            data = json.loads(row['payload'])
                            if isinstance(data.get('identity'), list):
                                data['identity'] = tuple(data['identity'])
                            self._audits[row['ip']] = data
            except (OSError, sqlite3.Error, ValueError, json.JSONDecodeError) as exc:
                self.error = f'No se pudo leer el registro de dispositivos: {exc}'

    def _connection(self):
        # sqlite3.Connection.__exit__ termina la transacción pero NO la cierra.
        from contextlib import closing
        conn = sqlite3.connect(self.path, timeout=3)
        conn.row_factory = sqlite3.Row
        return closing(conn)

    @staticmethod
    def _key(network, ip, mac):
        network = str(ipaddress.IPv4Network(network, strict=False))
        address = ipaddress.IPv4Address(ip)
        if address not in ipaddress.ip_network(network):
            raise ValueError('El dispositivo no pertenece a la subred indicada.')
        mac = normalize_mac(mac)
        return network, 'mac:' + mac if mac else 'ip:' + str(address)

    def get(self, network, ip, mac=''):
        key = self._key(network, ip, mac)
        with self.lock:
            record = self._records.get(key)
            return dict(record) if record else None

    def list_records(self):
        with self.lock:
            return [dict(row) for row in self._records.values()]

    def save(self, network, ip, mac, name, notes='', recognized=False):
        if self.error:
            raise ValueError(self.error + '. Conserva el archivo y revisa su estado antes de modificarlo.')
        network, identity = self._key(network, ip, mac)
        name, notes = str(name).strip(), str(notes).strip()
        if not name or len(name) > 80 or len(notes) > 500:
            raise ValueError('Escribe un nombre de 1–80 caracteres y notas de hasta 500 caracteres.')
        record = dict(network=network, identity=identity, ip=str(ipaddress.IPv4Address(ip)),
                      mac=normalize_mac(mac), name=name, notes=notes,
                      recognized=bool(recognized), updated=time.time())
        with self.lock:
            key = (network, identity)
            if key not in self._records and len(self._records) >= self.MAX_RECORDS:
                raise ValueError('Registro lleno. Olvida un dispositivo antes de añadir otro.')
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self._connection() as conn:
                    conn.execute('''CREATE TABLE IF NOT EXISTS devices (
                        network TEXT NOT NULL, identity TEXT NOT NULL, ip TEXT NOT NULL,
                        mac TEXT NOT NULL, name TEXT NOT NULL, notes TEXT NOT NULL,
                        recognized INTEGER NOT NULL, updated REAL NOT NULL,
                        PRIMARY KEY(network, identity))''')
                    conn.execute('''INSERT INTO devices VALUES (:network,:identity,:ip,:mac,:name,:notes,:recognized,:updated)
                        ON CONFLICT(network,identity) DO UPDATE SET ip=excluded.ip,mac=excluded.mac,
                        name=excluded.name,notes=excluded.notes,recognized=excluded.recognized,updated=excluded.updated''', record)
                    conn.commit()
            self._records[key] = record

    def forget(self, network, identity):
        if self.error:
            raise ValueError(self.error)
        with self.lock:
            if self.path and self.path.exists():
                with self._connection() as conn:
                    conn.execute('DELETE FROM devices WHERE network=? AND identity=?', (network, identity))
                    conn.commit()
            return self._records.pop((network, identity), None) is not None

    def list_audits(self):
        with self.lock:
            return [copy.deepcopy(row) for row in self._audits.values()]

    def save_audit(self, report):
        if self.error:
            raise ValueError(self.error + '. Conserva el archivo y revisa su estado antes de modificarlo.')
        snapshot = copy.deepcopy(report)
        ip = str(snapshot['ip'])
        finished = float(snapshot.get('finished') or snapshot.get('started') or time.time())
        with self.lock:
            self._audits.pop(ip, None)
            self._audits[ip] = snapshot
            while len(self._audits) > self.MAX_AUDITS:
                oldest = next(iter(self._audits))
                self._audits.pop(oldest, None)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self._connection() as conn:
                    conn.execute(
                        '''CREATE TABLE IF NOT EXISTS audits (
                            ip TEXT PRIMARY KEY,
                            finished REAL NOT NULL,
                            payload TEXT NOT NULL)'''
                    )
                    conn.execute(
                        '''INSERT INTO audits VALUES (:ip, :finished, :payload)
                           ON CONFLICT(ip) DO UPDATE SET finished=excluded.finished, payload=excluded.payload''',
                        dict(ip=ip, finished=finished, payload=json.dumps(snapshot, ensure_ascii=False)),
                    )
                    conn.execute(
                        'DELETE FROM audits WHERE ip NOT IN (SELECT ip FROM audits ORDER BY finished DESC LIMIT ?)',
                        (self.MAX_AUDITS,),
                    )
                    conn.commit()
