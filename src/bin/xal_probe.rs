// xal_probe: obtain an MBI_SSL ticket for user.auth.xboxlive.com via the
// Windows Authentication Broker (WAM), using the MSA the user is already
// signed into Windows with.
//
// This is a clean, documented, public-API path. The calling app is
// identified by its own Azure AD / Entra ID client ID (registered for
// "Personal Microsoft accounts" via portal.azure.com). No spoofing of
// Microsoft or third-party client IDs.
//
// Flow:
//   1. Find the MSA ("consumers") account provider:
//      FindAccountProviderWithAuthorityAsync("https://login.microsoft.com", "consumers")
//   2. Build a WebTokenRequest scoped to user.auth.xboxlive.com/MBI_SSL
//      with our own clientId.
//   3. GetTokenSilentlyAsync — silent token acquisition using the OS's
//      existing MSA session.
//   4. If the broker says UserInteractionRequired, escalate to
//      RequestTokenAsync (one-time interactive consent, cached by the OS).
//
// Output: MBI_SSL ticket printed to stdout, diagnostics to stderr.
//
// Docs:
//   https://learn.microsoft.com/en-us/windows/uwp/security/web-account-manager

use windows::core::HSTRING;
use windows::Security::Authentication::Web::Core::{
    WebAuthenticationCoreManager, WebTokenRequest, WebTokenRequestPromptType,
    WebTokenRequestResult, WebTokenRequestStatus,
};

// Registered at https://portal.azure.com → App registrations
// Account type: Personal Microsoft accounts only
// Public client flows: enabled
const CLIENT_ID: &str = "dbccc2ba-1cf6-48b8-bf7e-892d6ad6f6b3";

// Resource + policy for the legacy XBL user-auth endpoint. This is the
// MSA "compact ticket" format (service::<host>::<policy>) that returns an
// MBI_SSL ticket accepted by https://user.auth.xboxlive.com/user/authenticate.
const XBL_SCOPE: &str = "service::user.auth.xboxlive.com::MBI_SSL";

const MSA_PROVIDER_ID: &str = "https://login.microsoft.com";
const MSA_AUTHORITY_CONSUMERS: &str = "consumers";

fn main() -> windows::core::Result<()> {
    let provider = WebAuthenticationCoreManager::FindAccountProviderWithAuthorityAsync(
        &HSTRING::from(MSA_PROVIDER_ID),
        &HSTRING::from(MSA_AUTHORITY_CONSUMERS),
    )?
    .get()?;

    eprintln!("provider.Id:          {}", provider.Id()?);
    eprintln!("provider.DisplayName: {}", provider.DisplayName()?);
    eprintln!("provider.Authority:   {}", provider.Authority()?);

    let request = WebTokenRequest::CreateWithPromptType(
        &provider,
        &HSTRING::from(XBL_SCOPE),
        &HSTRING::from(CLIENT_ID),
        WebTokenRequestPromptType::Default,
    )?;

    eprintln!("Attempting silent token acquisition...");
    let result = WebAuthenticationCoreManager::GetTokenSilentlyAsync(&request)?.get()?;

    let status = result.ResponseStatus()?;
    eprintln!("silent status: {}", format_status(status));

    let result = if status == WebTokenRequestStatus::UserInteractionRequired {
        eprintln!("escalating to interactive RequestTokenAsync...");
        WebAuthenticationCoreManager::RequestTokenAsync(&request)?.get()?
    } else {
        result
    };

    report_and_emit(&result)
}

fn report_and_emit(result: &WebTokenRequestResult) -> windows::core::Result<()> {
    let status = result.ResponseStatus()?;
    eprintln!("final status: {}", format_status(status));

    if status != WebTokenRequestStatus::Success {
        if let Ok(err) = result.ResponseError() {
            eprintln!(
                "provider error: code=0x{:08x} message={}",
                err.ErrorCode()?,
                err.ErrorMessage().unwrap_or_default()
            );
        }
        return Err(windows::core::Error::from_hresult(windows::core::HRESULT(
            status.0,
        )));
    }

    let data = result.ResponseData()?;
    eprintln!("responses: {}", data.Size()?);

    for i in 0..data.Size()? {
        let resp = data.GetAt(i)?;
        let account = resp.WebAccount().ok();
        let account_user = account
            .as_ref()
            .and_then(|a| a.UserName().ok())
            .unwrap_or_default();
        let token = resp.Token()?;
        eprintln!(
            "  response[{}]: account={} token_len={}",
            i,
            account_user,
            token.len()
        );
        if i == 0 {
            // First token is the one we'll pipe to the MSA→XBL exchange.
            println!("{}", token);
        }
    }

    Ok(())
}

fn format_status(s: WebTokenRequestStatus) -> &'static str {
    match s.0 {
        0 => "Success",
        1 => "UserCancel",
        2 => "AccountSwitch",
        3 => "UserInteractionRequired",
        4 => "AccountProviderNotAvailable",
        5 => "ProviderError",
        _ => "<unknown>",
    }
}
