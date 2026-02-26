use serde_json::json;
use std::fs;

let input = json!({
    "attrs": [10,12,3,1],
    "r": "5",
    "threshold": "15",
    "weights": ["1","1","0","0"]
});

fs::write("../input.json", input.to_string()).unwrap();

println!("✅ input.json generated (without commitment)");