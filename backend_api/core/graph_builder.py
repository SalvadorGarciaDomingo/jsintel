from typing import Dict, Any, List

class GraphBuilder:
    def build(self, resultados: Dict[str, Any], objetivo: str, tipo: str) -> Dict[str, List[Dict[str, Any]]]:
        nodes = []
        edges = []
        def add_node(id_, label, color):
            nodes.append({"id": id_, "label": label, "color": color})
        def add_edge(a, b, label=""):
            e = {"from": a, "to": b}
            if label:
                e["label"] = label
            edges.append(e)
        root_id = f"root:{objetivo}"
        add_node(root_id, objetivo, "#00f7ff")
        user = resultados.get("user", {})
        if user.get("datos"):
            u = user["datos"]
            usuario = u.get("usuario") or u.get("username")
            if usuario:
                uid = f"user:{usuario}"
                add_node(uid, usuario, "#3b82f6")
                add_edge(root_id, uid, "usuario")
                for p in u.get("perfiles_encontrados", []) or []:
                    sitio = p.get("sitio")
                    url = p.get("url")
                    if sitio:
                        pid = f"account:{sitio}:{usuario}"
                        add_node(pid, sitio, "#1e40af")
                        add_edge(uid, pid, url or "cuenta")
                vip = u.get("vysion_im_profiles", {})
                for h in vip.get("hits", []) or []:
                    plat = h.get("platform") or "IM"
                    uname = ",".join(h.get("usernames", []) or [])
                    pid = f"im:{plat}:{h.get('userId')}"
                    add_node(pid, f"{plat} {uname}".strip(), "#0ea5e9")
                    add_edge(uid, pid, "perfil IM")
        domain = resultados.get("domain", {})
        if domain.get("datos"):
            d = domain["datos"]
            dom = d.get("dominio")
            if dom:
                did = f"domain:{dom}"
                add_node(did, dom, "#10b981")
                add_edge(root_id, did, "dominio")
                for s in d.get("subdominios", []) or []:
                    sid = f"sub:{s}"
                    add_node(sid, s, "#34d399")
                    add_edge(did, sid, "sub")
                for e in d.get("correos_relacionados", []) or []:
                    eid = f"email:{e}"
                    add_node(eid, e, "#6366f1")
                    add_edge(did, eid, "email")
                if d.get("ip_asociada"):
                    ipid = f"ip:{d['ip_asociada']}"
                    add_node(ipid, d["ip_asociada"], "#ef4444")
                    add_edge(did, ipid, "ip")
        ip = resultados.get("ip", {})
        if ip.get("datos"):
            i = ip["datos"].get("ip_api", {})
            ipaddr = i.get("ip")
            if ipaddr:
                iid = f"ip:{ipaddr}"
                add_node(iid, ipaddr, "#ef4444")
                add_edge(root_id, iid, "ip")
        email_primary = resultados.get("email", {})
        if email_primary.get("datos"):
            e = email_primary["datos"].get("email")
            if e:
                eid = f"email:{e}"
                add_node(eid, e, "#6366f1")
                add_edge(root_id, eid, "email")
        emails = resultados.get("emails", []) or []
        for item in emails:
            datos = item.get("datos", {})
            e = datos.get("email")
            if e:
                eid = f"email:{e}"
                add_node(eid, e, "#6366f1")
                add_edge(root_id, eid, "email")
        vysion = resultados.get("vysion", {})
        if vysion.get("datos"):
            v = vysion["datos"]
            for h in v.get("hits", []) or []:
                url = h.get("page", {}).get("url", {}).get("url") or ""
                title = h.get("page", {}).get("pageTitle") or "Resultado"
                vid = f"vysion:web:{abs(hash(url+title))}"
                add_node(vid, title, "#8b5cf6")
                add_edge(root_id, vid, url or "vysion")
            leaks = v.get("leaks", {})
            for l in leaks.get("hits", []) or []:
                lid = f"leak:{l.get('id')}"
                label = l.get("filePath") or "Leak"
                add_node(lid, label, "#7f1d1d")
                add_edge(root_id, lid, "leak")
        return {"nodes": nodes, "edges": edges}
