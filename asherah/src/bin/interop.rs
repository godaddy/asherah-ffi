#![allow(clippy::print_stdout)]
use anyhow::{anyhow, Context, Result};
use asherah as ael;
use base64::{engine::general_purpose::STANDARD, Engine as _};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let action = args.next().context("missing action (encrypt|decrypt)")?;
    let partition = args.next().context("missing partition id")?;
    let payload_b64 = args.next().context("missing payload base64")?;

    let payload = STANDARD
        .decode(payload_b64)
        .context("invalid base64 payload")?;

    let factory = ael::builders::factory_from_env()?;
    let session = factory.get_session(&partition);

    let output = match action.as_str() {
        "encrypt" => {
            let drr = session.encrypt(&payload)?;
            let json = serde_json::to_string(&drr).context("failed to serialize DataRowRecord")?;
            STANDARD.encode(json)
        }
        "decrypt" => {
            let json = String::from_utf8(payload).context("payload not valid UTF-8")?;
            let drr: ael::types::DataRowRecord =
                serde_json::from_str(&json).context("failed to parse DataRowRecord JSON")?;
            let plaintext = session.decrypt(drr)?;
            STANDARD.encode(plaintext)
        }
        other => return Err(anyhow!("unknown action: {other}")),
    };

    drop(session);
    factory.close().map_err(|e| anyhow!(e))?;
    println!("{}", output);
    Ok(())
}
