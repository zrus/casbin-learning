#![allow(warnings)]

use std::error::Error;

use casbin::{rhai::ImmutableString, CoreApi, Enforcer, MgmtApi, RbacApi};
use once_cell::sync::OnceCell;
use route_recognizer::Router;

pub static ENFORCER: OnceCell<Enforcer> = OnceCell::new();
pub static POLICIES: OnceCell<Router<()>> = OnceCell::new();

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
  let mut enforcer = Enforcer::new("model.conf", "policies.csv").await?;
  enforcer.add_function("resourceMatch", |key1, key2| {
    let enforcer = ENFORCER.get().unwrap();
    let policies = enforcer.get_filtered_named_grouping_policy("g2", 1, vec![key2.to_string()]);
    println!("{policies:?}");
    let mut routers = Router::<()>::new();
    for policy in policies {
      routers.add(&policy[0], ());
      println!("{}", policy[0]);
      if routers.recognize(key1.as_str()).is_ok() {
        return true;
      }
    }
    false
  });
  ENFORCER.set(enforcer).map_err(|_| {}).unwrap();

  let result = ENFORCER
    .get()
    .unwrap()
    .enforce(("domain_user_admin", "/users", "GET"))?;
  println!("{result:?}");

  Ok(())
}
