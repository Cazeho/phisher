#[macro_use] extern crate rocket;

use rocket::fs::{FileServer, relative};
use rocket::form::Form;
use rocket::serde::{Serialize, Deserialize};
use rocket_dyn_templates::{Template, context};
use std::process::Command;
use thirtyfour::prelude::*;
use tokio;
use std::path::Path;
use reqwest::Client;
use serde_json::Value;

// Struct to handle the form input
#[derive(Debug, FromForm, Serialize, Deserialize)]
struct UrlSubmission {
    url: String,
}

// Struct to represent the extracted form input fields
#[derive(Debug, Serialize, Deserialize)]
struct FormInput {
    name: Option<String>,
    id: Option<String>,
    input_type: Option<String>,
}

// Struct to store the URL scan result
#[derive(Debug, Serialize, Deserialize)]
struct UrlScanResult {
    task_time: String,
    task_url: String,
    result_url: String,
    uuid: String,
}

// Function to get urlscan.io results for a given domain
async fn get_urlscan_results(domain: &str, client: &Client) -> Vec<UrlScanResult> {
    let api_url = format!("https://urlscan.io/api/v1/search/?q=domain:{}", domain);
    let res = client.get(&api_url).send().await.unwrap();
    let json_data: Value = res.json().await.unwrap();

    let mut url_scan_results = vec![];
    if let Some(results) = json_data["results"].as_array() {
        for result in results {
            let task_time = result["task"]["time"].as_str().unwrap_or("N/A").to_string();
            let task_url = result["task"]["url"].as_str().unwrap_or("N/A").to_string();
            let uuid = result["task"]["uuid"].as_str().unwrap_or("N/A").to_string();

            // Create a link to the result page using the UUID
            let result_url = format!("https://urlscan.io/result/{}", uuid);

            url_scan_results.push(UrlScanResult {
                task_time,
                task_url,
                result_url,
                uuid,
            });
        }
    }

    url_scan_results
}

// Function to get VirusTotal score for a given domain
async fn get_virustotal_score(domain: &str, api_key: &str, client: &Client) -> u64 {
    let virustotal_api_url = format!(
        "https://www.virustotal.com/vtapi/v2/domain/report?apikey={}&domain={}",
        api_key, domain
    );
    let vt_res = client.get(&virustotal_api_url).send().await.unwrap();
    let vt_json: Value = vt_res.json().await.unwrap();

    // Extract the reputation score or number of positives from VirusTotal
    vt_json["positives"].as_u64().unwrap_or(0) // Number of positives if available
}

// Function to extract form inputs from a webpage
async fn extract_form_inputs(driver: &WebDriver) -> Vec<FormInput> {
    let mut form_inputs = vec![];

    // Try to find a form on the page
    if let Ok(form) = driver.find(By::Tag("form")).await {
        let input_elements = form.find_all(By::Tag("input")).await.unwrap();

        for input in input_elements {
            let name = input.attr("name").await.unwrap_or(None);
            let id = input.attr("id").await.unwrap_or(None);
            let input_type = input.attr("type").await.unwrap_or(None);

            form_inputs.push(FormInput {
                name,
                id,
                input_type,
            });
        }
    }

    form_inputs
}

// Main function that handles the form submission, URL scan, VirusTotal score retrieval, and form extraction
#[post("/submit", data = "<url_submission>")]
async fn submit(url_submission: Form<UrlSubmission>) -> Template {
    let url = url_submission.url.clone();

    // Start ChromeDriver (ensure it's in the bin directory)
    let mut chromedriver = Command::new("./bin/chromedriver")
        .arg("--port=9515")
        .spawn()
        .expect("Failed to start chromedriver");

    // Give ChromeDriver some time to start
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Use Selenium to open the submitted URL and get the page title
    let caps = DesiredCapabilities::chrome();
    let driver = WebDriver::new("http://localhost:9515", caps).await.unwrap();

    // Navigate to the submitted URL
    driver.goto(&url).await.unwrap();

    // Get the page title
    let title = driver.title().await.unwrap();

    // Define the screenshot path
    let screenshot_path = format!("./screenshots/screenshot.png");
    let path = Path::new(&screenshot_path);

    // Take a screenshot and save it directly to the specified path
    driver.screenshot(path).await.unwrap();

    // Extract form inputs
    let form_inputs = extract_form_inputs(&driver).await;

    // Quit the driver and stop the chromedriver
    driver.quit().await.unwrap();
    chromedriver.kill().expect("Failed to kill chromedriver");

    // Extract the domain from the submitted URL
    let domain = url.split("//").nth(1).unwrap_or("").split('/').next().unwrap_or("");

    // Initialize HTTP client
    let client = Client::new();

    // Get URL scan results from urlscan.io
    let url_scan_results = get_urlscan_results(domain, &client).await;

    // Get VirusTotal score
    let virustotal_api_key = "7b6e2f3c3a8067581502a841b1a06346772e12c263d49a41e60f948a5b83d6cb"; // Replace with your actual VirusTotal API key
    let virustotal_score = get_virustotal_score(domain, virustotal_api_key, &client).await;

    // Render the `result.html.tera` template and pass the title, url, screenshot path, form inputs, and API results
    Template::render("result", context! {
        url: url,
        title: title,
        screenshot_path: "/screenshots/screenshot.png",
        form_present: !form_inputs.is_empty(),
        form_inputs: form_inputs,
        url_scan_results: url_scan_results,
        virustotal_score: virustotal_score
    })
}

#[get("/")]
fn index() -> Template {
    // Render the index page where the user can submit a URL
    Template::render("index", context! {})
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![index, submit])
        .mount("/screenshots", FileServer::from(relative!("screenshots")))
        .attach(Template::fairing())
}
