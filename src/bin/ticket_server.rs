// ticket_server: localhost HTTP endpoint that returns a fresh MBI_SSL
// ticket for user.auth.xboxlive.com, minted via WAM against the OS's
// MSA session.
//
// Protocol:
//   GET /ticket  -> 200 { "ticket": "<MBI_SSL compact>", "account": "<user>" }
//                -> 500 { "error": "<message>" }
//   GET /health  -> 200 "ok"
//
// Single-threaded by design: WAM returns in a few ms from cache, and
// serializing requests keeps WinRT apartment state simple.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

use windows::core::HSTRING;
use windows::Security::Authentication::Web::Core::{
    WebAuthenticationCoreManager, WebTokenRequest, WebTokenRequestPromptType,
    WebTokenRequestResult, WebTokenRequestStatus,
};
use windows::Win32::System::Console::GetConsoleWindow;
use windows::Win32::System::WinRT::IWebAuthenticationCoreManagerInterop;
use windows_future::IAsyncOperation;

const CLIENT_ID: &str = "dbccc2ba-1cf6-48b8-bf7e-892d6ad6f6b3";
const XBL_SCOPE: &str = "service::user.auth.xboxlive.com::MBI_SSL";
const MSA_PROVIDER_ID: &str = "https://login.microsoft.com";
const MSA_AUTHORITY_CONSUMERS: &str = "consumers";

const BIND: &str = "127.0.0.1:8099";

fn main() {
    let listener = match TcpListener::bind(BIND) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {} failed: {}", BIND, e);
            std::process::exit(1);
        }
    };
    eprintln!("xct-win8bridge ticket_server listening on http://{}", BIND);

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Err(e) = handle(s) {
                    eprintln!("request error: {}", e);
                }
            }
            Err(e) => eprintln!("accept error: {}", e),
        }
    }
}

fn handle(mut stream: TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    // Drain remaining request headers until empty line
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n <= 2 {
            break;
        }
    }

    let method_path: Vec<&str> = request_line.split_whitespace().collect();
    let path = method_path.get(1).copied().unwrap_or("");

    match path {
        "/health" => {
            write_response(&mut stream, 200, "text/plain", b"ok")
        }
        "/ticket" => {
            match get_msa_ticket() {
                Ok((ticket, account)) => {
                    let body = format!(
                        r#"{{"ticket":{},"account":{}}}"#,
                        json_string(&ticket),
                        json_string(&account)
                    );
                    write_response(&mut stream, 200, "application/json", body.as_bytes())
                }
                Err(msg) => {
                    let body = format!(r#"{{"error":{}}}"#, json_string(&msg));
                    eprintln!("ticket error: {}", msg);
                    write_response(&mut stream, 500, "application/json", body.as_bytes())
                }
            }
        }
        _ => write_response(&mut stream, 404, "text/plain", b"not found"),
    }
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Status",
    };
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        reason,
        content_type,
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

/// Minimal JSON string escape for ASCII content (tickets/account names).
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn get_msa_ticket() -> Result<(String, String), String> {
    let provider = WebAuthenticationCoreManager::FindAccountProviderWithAuthorityAsync(
        &HSTRING::from(MSA_PROVIDER_ID),
        &HSTRING::from(MSA_AUTHORITY_CONSUMERS),
    )
    .map_err(|e| format!("FindAccountProvider: {}", e))?
    .get()
    .map_err(|e| format!("FindAccountProvider.get: {}", e))?;

    let request = WebTokenRequest::CreateWithPromptType(
        &provider,
        &HSTRING::from(XBL_SCOPE),
        &HSTRING::from(CLIENT_ID),
        WebTokenRequestPromptType::Default,
    )
    .map_err(|e| format!("CreateWithPromptType: {}", e))?;

    let result = WebAuthenticationCoreManager::GetTokenSilentlyAsync(&request)
        .map_err(|e| format!("GetTokenSilentlyAsync: {}", e))?
        .get()
        .map_err(|e| format!("GetTokenSilentlyAsync.get: {}", e))?;

    let status = result
        .ResponseStatus()
        .map_err(|e| format!("ResponseStatus: {}", e))?;

    // Escalate to interactive prompt only if the broker tells us it needs
    // user interaction — e.g. first-time consent. WebAuthenticationCoreManager
    // is a UWP API that wants a CoreWindow by default; console (Win32) apps
    // have no CoreWindow, so a plain RequestTokenAsync returns 0x80073B27.
    // The interop interface's RequestTokenForWindowAsync takes an HWND
    // instead, which is exactly the "desktop-app entry point" we need.
    // GetConsoleWindow() yields our parent console's HWND under `start /B`.
    let result = if status == WebTokenRequestStatus::UserInteractionRequired {
        eprintln!("silent failed: UserInteractionRequired; prompting user once...");
        let interop: IWebAuthenticationCoreManagerInterop =
            windows::core::factory::<WebAuthenticationCoreManager, IWebAuthenticationCoreManagerInterop>()
                .map_err(|e| format!("factory IWebAuthenticationCoreManagerInterop: {}", e))?;
        let hwnd = unsafe { GetConsoleWindow() };
        eprintln!("using parent HWND {:?} for WAM consent dialog", hwnd.0);
        if hwnd.0.is_null() {
            return Err("GetConsoleWindow() returned NULL -- nothing to parent the WAM consent dialog to. \
                This usually means ticket_server was started detached. Run it from a visible cmd window for first-time consent.".into());
        }
        let async_op = unsafe {
            interop
                .RequestTokenForWindowAsync::<_, IAsyncOperation<WebTokenRequestResult>>(
                    hwnd, &request,
                )
                .map_err(|e| format!("RequestTokenForWindowAsync: {}", e))?
        };
        async_op
            .get()
            .map_err(|e| format!("RequestTokenForWindowAsync.get: {}", e))?
    } else {
        result
    };

    let status = result
        .ResponseStatus()
        .map_err(|e| format!("ResponseStatus: {}", e))?;
    if status != WebTokenRequestStatus::Success {
        let err = result.ResponseError().ok();
        let code = err.as_ref().and_then(|e| e.ErrorCode().ok()).unwrap_or(0);
        let msg = err
            .as_ref()
            .and_then(|e| e.ErrorMessage().ok())
            .map(|h| h.to_string())
            .unwrap_or_else(|| "no message".into());
        return Err(format!(
            "status={} provider_code=0x{:08x} msg={}",
            status.0, code, msg
        ));
    }

    let data = result
        .ResponseData()
        .map_err(|e| format!("ResponseData: {}", e))?;
    if data.Size().map_err(|e| format!("Size: {}", e))? == 0 {
        return Err("response contained no tokens".into());
    }
    let resp = data.GetAt(0).map_err(|e| format!("GetAt(0): {}", e))?;
    let ticket = resp
        .Token()
        .map_err(|e| format!("Token: {}", e))?
        .to_string();
    let account = resp
        .WebAccount()
        .ok()
        .and_then(|a| a.UserName().ok())
        .map(|h| h.to_string())
        .unwrap_or_default();

    Ok((ticket, account))
}
