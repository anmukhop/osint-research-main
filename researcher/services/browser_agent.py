from playwright.sync_api import sync_playwright


def search_username(username: str, headless: bool = True) -> dict:
    """
    Search for a username on whatsmyname.pro and return results.

    Args:
        username: The username to search for
        headless: Run browser invisibly (True) or visibly (False)
    
    Returns:
        dict with username, found sites, num of found sites, and any errors.
    """
    results = {
        "username": username,
        "found_sites": [],
        "total_found": 0,
        "error": None
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        page = browser.new_page()

        try: 
            # 1. Navigate to the site
            print("Navigating to site...")
            page.goto("https://whatsmyname.pro/", timeout=60000)
            page.wait_for_load_state("domcontentloaded", timeout=60000)
            print("Page loaded")

            # 2. Find and fill the search input
            print("Looking for input...")
            search_input = page.locator("input[placeholder*='username']")
            search_input.fill(username, timeout=30000)
            print("Filled username")

            # 3. Click the search button
            print("Clicking search...")
            search_button = page.get_by_role("button", name="Search")
            search_button.click(timeout=30000)
            print("Clicked search")

            # 4. Wait for search to complete
            print("Waiting for progress...")
            page.wait_for_selector("text=Progress: 100", timeout=300000)
            print("Search complete")

            #5. Give it a moment to fully render results
            page.wait_for_timeout(2000)

            #6. Click the "found" filter to show matches only
            found_tab = page.locator("button:has-text('Found')").first
            found_tab.click()
            page.wait_for_timeout(3000)

            #7. Scrape all result cards
            cards = page.locator("div.result-card.found").all()
            
            for card in cards:
                try:
                    # Get platform name from h3.site-name
                    platform_name = card.locator("h3.site-name").inner_text(timeout=10000)
                    
                    # Get domain from the favicon img src
                    favicon = card.locator("img.logo-img").first
                    favicon_src = favicon.get_attribute("src") if favicon.count() > 0 else ""
                    
                    # Extract domain from: https://www.google.com/s2/favicons?domain=www.threads.com&sz=32
                    domain = "Unknown"
                    if "domain=" in favicon_src:
                        domain = favicon_src.split("domain=")[1].split("&")[0]
                    
                    results["found_sites"].append({
                        "platform": platform_name.strip(),
                        "domain": domain,
                        "profile_url": f"https://{domain}/{username}"
                    })
                except Exception:
                    continue
                    
            results["total_found"] = len(results["found_sites"])

        except Exception as e:
            results["error"] = str(e)
        finally:
            browser.close()
        
    return results

# Test the function
if __name__ == "__main__":
    print("Searching for username: test_user")
    print("Browser will open so you can watch...")
    
    results = search_username("test_user", headless=False)
    
    if results["error"]:
        print(f"\nError: {results['error']}")
    else:
        print(f"\nFound {results['total_found']} sites:")
        for site in results["found_sites"]:
            print(f"  - {site['platform']}: {site['domain']}")
        """
        if results["total_found"] > 10:
            print(f"  ... and {results['total_found'] - 10} more")
        """