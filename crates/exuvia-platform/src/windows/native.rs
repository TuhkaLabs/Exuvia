use std::process::Command;

use exuvia_core::{AppSource, ExuviaError, InstalledApp, Result};

use crate::NativeUninstallOutcome;

pub fn native_uninstall(app: &InstalledApp) -> Result<NativeUninstallOutcome> {
    let quiet = app
        .uninstall
        .quiet_uninstall_string
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let uninstall = app
        .uninstall
        .uninstall_string
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if app.source == AppSource::Msi {
        if let Some(product_code) = &app.product_code {
            if let Some(command) = quiet {
                return run_shell(command);
            }
            return run_msiexec(product_code);
        }
    }

    if let Some(command) = quiet {
        return run_shell(command);
    }
    if let Some(command) = uninstall {
        return run_shell(command);
    }

    Ok(NativeUninstallOutcome::NotAvailable)
}

fn run_shell(command: &str) -> Result<NativeUninstallOutcome> {
    let status = Command::new("cmd")
        .arg("/C")
        .arg(command)
        .status()
        .map_err(|error| ExuviaError::io("failed to start the application uninstaller", error))?;

    Ok(NativeUninstallOutcome::Ran {
        command: command.to_string(),
        exit_code: status.code(),
        success: is_success(status.code()),
    })
}

fn run_msiexec(product_code: &str) -> Result<NativeUninstallOutcome> {
    let status = Command::new("msiexec")
        .arg("/x")
        .arg(product_code)
        .arg("/qn")
        .arg("/norestart")
        .status()
        .map_err(|error| ExuviaError::io("failed to start msiexec", error))?;

    Ok(NativeUninstallOutcome::Ran {
        command: format!("msiexec /x {product_code} /qn /norestart"),
        exit_code: status.code(),
        success: is_success(status.code()),
    })
}

fn is_success(code: Option<i32>) -> bool {
    // 3010 = reboot required, 1641 = reboot initiated.
    matches!(code, Some(0) | Some(3010) | Some(1641))
}
