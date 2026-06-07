import { useEffect, useState } from "react";
import { TenantView, api, setActiveTenant } from "../api";

// Workspace (tenant) switcher. Changing the active tenant re-points every scoped API call
// at that tenant via the X-Tenant-Id header; the backend enforces the isolation boundary,
// so switching here can never surface another tenant's runs unless they belong to it.
export function TenantSwitcher({
  active,
  onChange,
}: {
  active: string;
  onChange: (tenantId: string) => void;
}) {
  const [tenants, setTenants] = useState<TenantView[]>([]);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function load() {
    try {
      const res = await api.listTenants();
      setTenants(res.tenants);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  useEffect(() => {
    load();
  }, []);

  function select(id: string) {
    setActiveTenant(id);
    onChange(id);
  }

  async function create() {
    if (!name.trim()) return;
    setError(null);
    try {
      const t = await api.createTenant(name.trim());
      setName("");
      setCreating(false);
      await load();
      select(t.tenant_id);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className="tenant-switcher">
      <label className="tenant-label">Workspace</label>
      <select value={active} onChange={(e) => select(e.target.value)}>
        {tenants.map((t) => (
          <option key={t.tenant_id} value={t.tenant_id}>
            {t.display_name}
          </option>
        ))}
      </select>
      {creating ? (
        <div className="tenant-create">
          <input
            value={name}
            placeholder="New workspace name"
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && create()}
          />
          <button onClick={create}>Add</button>
          <button className="ghost" onClick={() => setCreating(false)}>
            ×
          </button>
        </div>
      ) : (
        <button className="ghost" onClick={() => setCreating(true)}>
          + New workspace
        </button>
      )}
      {error && <div className="tenant-error">{error}</div>}
    </div>
  );
}
