// Package operations declares Warden's canonical functional operation surface.
package operations
import ("github.com/gantry-tools/gantry-core/contracttest"; "github.com/gantry-tools/gantry-core/operation")
var Contracts = []operation.Contract{
	contract("warden.setup.status", operation.Read, "GET", "/api/setup/status", "setup", "status", operation.Public, ""),
	contract("warden.alerts.update", operation.Mutation, "POST", "/api/alerts", "alerts", "update", operation.Session, "warden.alerts.updated"),
	contract("warden.users.manage", operation.Destructive, "POST", "/api/manage/users/action", "users", "manage", operation.Capability, "warden.users.managed"),
}
func contract(id string, kind operation.Kind, method, path, resource, verb string, boundary operation.Boundary, event string) operation.Contract { audit:=operation.Audit{}; if kind!=operation.Read { audit=operation.Audit{Required:true,Event:event} }; auth:=operation.Authorization{Boundary:boundary}; if boundary==operation.Capability { auth.Capability="accounts.manage" }; return operation.Contract{SchemaVersion:operation.SchemaVersion,ID:id,Kind:kind,Route:operation.Route{Method:method,Path:path},CLI:&operation.CLI{Resource:resource,Verb:verb},Authorization:auth,Audit:audit,Idempotency:operation.Idempotency{RetrySafe:kind==operation.Read},Automation:operation.Automatable} }
func AdoptionManifest() contracttest.Manifest { routes:=make([]operation.Route,len(Contracts)); ids:=make([]string,len(Contracts)); for i,c:=range Contracts { routes[i],ids[i]=c.Route,c.ID }; return contracttest.Manifest{SchemaVersion:1,Project:"warden",Operations:Contracts,ObservedRoutes:routes,WebsiteOperations:ids} }
