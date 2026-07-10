import { Plus, Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { createUser, deleteUser, fetchUsers } from '../../api';
import { de } from '../../i18n/de';
import type { UserEntry } from '../../types';

export default function UsersPanel() {
  const [users, setUsers] = useState<UserEntry[]>([]);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('viewer');
  const [status, setStatus] = useState<string | null>(null);

  const reload = () => fetchUsers().then(setUsers);
  useEffect(() => { reload(); }, []);

  async function add() {
    try {
      await createUser(username.trim(), password, role);
      setUsername('');
      setPassword('');
      setStatus(null);
      await reload();
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    }
  }

  async function remove(id: number) {
    try {
      await deleteUser(id);
      await reload();
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    }
  }

  return (
    <div className="fwpt-card space-y-3">
      <h2 className="font-medium text-slate-100">{de.settings.users}</h2>
      <table className="w-full text-left text-sm">
        <tbody>
          {users.map((u) => (
            <tr key={u.id} className="border-b border-slate-800/60">
              <td className="py-1.5 text-slate-200">{u.username}</td>
              <td className="py-1.5 text-slate-400">{u.role}</td>
              <td className="py-1.5 text-right">
                <button type="button" className="text-slate-500 hover:text-red-400"
                  onClick={() => remove(u.id)}>
                  <Trash2 size={15} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="flex flex-wrap items-center gap-2">
        <input className="fwpt-input !w-40" placeholder={de.login.username} value={username}
          onChange={(e) => setUsername(e.target.value)} />
        <input className="fwpt-input !w-40" type="password" placeholder={de.login.password}
          value={password} onChange={(e) => setPassword(e.target.value)} />
        <select className="fwpt-input !w-28" value={role} onChange={(e) => setRole(e.target.value)}>
          <option value="viewer">viewer</option>
          <option value="admin">admin</option>
        </select>
        <button type="button" className="fwpt-btn" disabled={!username.trim() || password.length < 8}
          onClick={add}>
          <Plus size={14} /> Anlegen
        </button>
      </div>
      {status && <p className="text-sm text-red-400">{status}</p>}
    </div>
  );
}
