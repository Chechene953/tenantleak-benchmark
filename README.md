# tenantleak-benchmark

Un banc d'essai ouvert pour les fuites de données **entre clients** d'un SaaS (isolation multi-tenant, BOLA/IDOR
entre organisations, OWASP API1) : cinq cibles volontairement vulnérables et un corrigé écrit à l'avance.

*An open benchmark for cross-tenant data leaks in multi-tenant SaaS: five deliberately vulnerable targets (REST,
GraphQL, Supabase, an MCP server, a RAG assistant) and an answer key written in advance. Run them locally or use the
hosted copy, run your tool, score it with `tlbench score`.*

- **20 fuites plantées** à trouver ;
- **21 opérations correctement protégées** : une alerte y est une fausse alerte (dont des pièges : un catalogue
  public par conception, une erreur qui répète l'identifiant demandé, un assistant corrigé) ;
- **3 outils MCP à ne jamais appeler** (destructif, écriture) ;
- les failles hors périmètre sont listées à part et ne comptent pas.

Résultats publiés : <https://tenantleak.redsentinel.fr/benchmark>. Nous avons écrit ces cibles et notre outil a été
développé en s'en servant : son score parfait est un minimum, pas une preuve. Les résultats de tout autre outil seront
publiés, bons ou mauvais pour nous : ouvrez une *issue* avec votre fichier de soumission.

## Lancer les cibles

```bash
pip install .            # ou : docker build -t tlbench . && docker run -p 8100:8100 tlbench
tlbench serve            # http://127.0.0.1:8100/ liste les cibles, leurs URL et les comptes de test
```

Copie hébergée (données factices remises à zéro toutes les 10 minutes, débit limité) :
<https://tenantleak.redsentinel.fr/bench/>

| Cible | Base | Comptes de test (client acme / client globex) |
|---|---|---|
| API REST | `/rest` (spec : `/rest/openapi.json`, GraphQL : `/rest/graphql`) | `Bearer tok-alice` / `Bearer tok-bob` ; en-tête de client `X-Tenant-Id` |
| Supabase | `/supabase` (`/rest/v1`, `/auth/v1`) | `alice@acme.test` / `alice-pass`, `bob@globex.test` / `bob-pass`, clé anon donnée par `/` |
| Serveur MCP | `/mcp/mcp` (Streamable HTTP) | `Bearer tok-acme` / `Bearer tok-globex` |
| Assistant RAG | `POST /rag/api/chat` `{"message": "…"}` | `Bearer tok-acme` / `Bearer tok-globex` |

Sur l'assistant, chaque client a déjà un document témoin dans sa base : `Azurite-6926` (code `TLC-BYK7-JZMF`) pour
acme, `Opaline-D599` (code `TLC-7UGG-FSLE`) pour globex. La fuite à démontrer : obtenir le code de l'un depuis le
compte de l'autre.

## Noter un outil

Écrivez ses résultats au format de `results/tenantleak.json` :

```json
{"tool": "mon-outil", "version": "1.0", "targets": ["rest", "supabase"],
  "findings": [{"target": "rest", "op": "GET /api/projects/{project_id}", "kind": "cross_tenant_read"}],
  "called": ["list_projects", "get_project"]}
```

puis `tlbench score resultats.json`. Les opérations s'écrivent comme dans `tlbench/cases.json`
(`METHOD chemin`, `QUERY /graphql#champ`, `TOOL /mcp/tools/<nom>`, `ASK /api/chat`) ; `kind` est facultatif
(sans lui, une alerte vaut pour tous les cas de l'opération, pièges compris). Les cibles absentes de `targets`
sont « non testées » et ne comptent ni pour ni contre.

Score de référence (`results/tenantleak.json`, tenantleak 0.3.2, tenantleak-cloud 1.3.0) : 20/20 fuites trouvées,
0/21 fausse alerte, 0/3 outil interdit appelé.

## Corrigé

| Cible | Opération | Attendu | Cas |
|---|---|---|---|
| `rest` | `GET /api/projects/{project_id}` | leak | Projet d'un autre client lu par son identifiant |
| `rest` | `PATCH /api/projects/{project_id}` | leak | Projet d'un autre client modifié |
| `rest` | `GET /api/users/{user_id}` | leak | Fiche d'un utilisateur d'un autre client (données personnelles) |
| `rest` | `GET /api/reports/{report_id}/export` | leak | Export de rapport sans authentification |
| `rest` | `GET /api/reports/{report_id}/export` | leak | Export de rapport d'un autre client |
| `rest` | `GET /api/search` | leak | Recherche qui croit le paramètre tenant_id |
| `rest` | `GET /api/contracts/{contract_id}` | leak | Contrat sans liste, joignable seulement par l'identifiant cité dans un projet |
| `rest` | `GET /api/workspace/settings` | leak | Réglages d'un autre client via l'en-tête X-Tenant-Id |
| `rest` | `GET /api/workspace/members` | leak | Membres d'un autre client via l'en-tête X-Tenant-Id |
| `rest` | `PATCH /api/notes/{note_id}` | leak | Note déplacée chez un autre client par son champ tenant_id |
| `rest` | `POST /api/comments` | leak | Commentaire accepté sur le projet d'un autre client |
| `rest` | `GET /api/me` | leak | Clé d'API renvoyée en clair |
| `rest` | `GET /api/invoices/{invoice_id}` | safe | Facture : contrôle du client correct |
| `rest` | `GET /api/projects/{project_id}/documents/{document_id}` | safe | Document d'un projet : contrôle correct |
| `rest` | `GET /api/projects/{project_id}/documents` | safe | Documents d'un projet : liste filtrée |
| `rest` | `GET /api/notes/{note_id}` | safe | Note : lecture contrôlée |
| `rest` | `GET /api/projects` | safe | Liste des projets filtrée par client |
| `rest` | `GET /api/invoices` | safe | Liste des factures filtrée par client |
| `rest` | `GET /api/users` | safe | Liste des utilisateurs filtrée par client |
| `rest` | `GET /api/reports` | safe | Liste des rapports filtrée par client |
| `graphql` | `QUERY /graphql#project` | leak | project(id) sans contrôle du client |
| `graphql` | `QUERY /graphql#node` | leak | node(id) Relay : contourne invoice(id), pourtant protégé |
| `graphql` | `QUERY /graphql#me` | leak | apiKey renvoyée en clair |
| `graphql` | `QUERY /graphql#invoice` | safe | invoice(id) : contrôle correct |
| `graphql` | `QUERY /graphql#invoices` | safe | invoices (connexion Relay) filtrée |
| `graphql` | `QUERY /graphql#projects` | safe | projects filtrée |
| `supabase` | `GET /rest/v1/invoices` | leak | Table sans RLS : lignes d'un autre client |
| `supabase` | `GET /rest/v1/invoices` | leak | Table sans RLS : lisible avec la seule clé publique |
| `supabase` | `GET /rest/v1/documents` | leak | Politique « tout utilisateur connecté » sans contrôle du propriétaire |
| `supabase` | `GET /rest/v1/documents` | safe | documents : rien sans connexion |
| `supabase` | `GET /rest/v1/projects` | safe | projects : RLS par organisation correcte |
| `supabase` | `GET /rest/v1/profiles` | safe | profiles : chacun voit le sien |
| `supabase` | `GET /rest/v1/members` | safe | members : chacun voit les siens |
| `supabase` | `GET /rest/v1/plans` | safe | plans : catalogue public par conception (piège) |
| `mcp` | `TOOL /mcp/tools/get_project` | leak | Outil get_project sans contrôle du client (cas Asana MCP) |
| `mcp` | `TOOL /mcp/tools/get_invoice` | safe | get_invoice : refuse, en répétant l'identifiant demandé (piège) |
| `mcp` | `TOOL /mcp/tools/list_projects` | safe | list_projects filtrée |
| `mcp` | `TOOL /mcp/tools/list_invoices` | safe | list_invoices filtrée (argument enum requis) |
| `mcp` | `delete_project` | never_called | Outil annoté destructif : jamais appelé |
| `mcp` | `create_note` | never_called | Outil d'écriture sans annotation : jamais appelé |
| `mcp` | `get_status` | never_called | Outil annoté readOnlyHint: false : jamais appelé |
| `rag` | `ASK /api/chat` | leak | Index vectoriel partagé : le document témoin d'un client sort chez l'autre |
| `rag` | `ASK /api/chat` | safe | Assistant fermé sans connexion |
| `rag_fixed` | `ASK /api/chat` | safe | Assistant corrigé (filtre par client) : aucune alerte attendue |

Hors périmètre :

- `GET /api/admin/audit-logs` : Un membre lit un journal réservé aux administrateurs de son propre client : contrôle de rôle, pas d'isolation entre clients.
- `JWT « alg: none »` : Des jetons forgés sans signature sont acceptés : faille d'authentification, hors du test d'isolation.

## Licence

Apache-2.0. Les cibles sont générées depuis tenantleak Cloud (RedSentinel) ; elles ne contiennent que des données
factices. Ne les exposez pas sur un réseau où elles pourraient être confondues avec un vrai service.
