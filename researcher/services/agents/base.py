"""
Base Browser Agent for OSINT Research Platform

Provides shared Playwright functionality that all site-specific agents inherit.
"""

from abc import ABC, abstractmethod
from playwright.sync_api import sync_playwright, Browser, Page
from typing import Any

class BaseBrowserAgent(ABC):
    """
    Abstract base class for browser-based OSINT agents.
    
    Handles common Playwright setup/teardown and provides
    a consistent interface for all agents.
    """

    def __init__(self, headless: bool = True, timeout: int = 60000):
        """
        Initialize the agent.
        
        Args:
            headless: Run browser invisibly (True) or visibly (False)
            timeout: Default timeout in milliseconds for operations
        """
        self.headless = headless
        self.timeout = timeout
        self.browser: Browser | None = None
        self.page: Page | None = None
        self._playwright = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Agent identifier (e.g., 'whatsmyname', 'fastpeoplesearch')"""
        pass
    
    @property
    @abstractmethod
    def base_url(self) -> str:
        """The target site URL"""
        pass

    @abstractmethod
    def execute(self, **kwargs) -> dict:
        """
        Execute the search with given parameters.
        
        Returns:
            dict with results, must include 'error' key (None if successful)
        """
        pass

    def _start_browser(self) -> None:
        """Start Playwright and launch browser."""
        self._playwright = sync_playwright().start()
        self.browser = self._playwright.chromium.launch(headless=self.headless)
        self.page = self.browser.new_page()

    def _stop_browser(self) -> None:
        """Close browser and stop Playwright."""
        if self.browser:
            self.browser.close()
        if self._playwright:
            self._playwright.stop()
        self.browser = None
        self.page = None
        self._playwright = None

    def _navigate(self, url: str | None = None) -> None:
        """
        Navigate to URL (defaults to base_url).
        
        Args:
            url: URL to navigate to, or None to use base_url
        """
        target = url or self.base_url
        self.page.goto(target, timeout=self.timeout)
        self.page.wait_for_load_state("domcontentloaded", timeout=self.timeout)
    
    def _wait_for_selector(self, selector: str, timeout: int | None = None) -> None:
        """Wait for an element to appear."""
        self.page.wait_for_selector(selector, timeout=timeout or self.timeout)
    
    def _click(self, selector: str, timeout: int | None = None) -> None:
        """Click an element."""
        self.page.locator(selector).click(timeout=timeout or self.timeout)
    
    def _fill(self, selector: str, value: str, timeout: int | None = None) -> None:
        """Fill an input field."""
        self.page.locator(selector).fill(value, timeout=timeout or self.timeout)
    
    def _get_text(self, selector: str, timeout: int | None = None) -> str:
        """Get text content of an element."""
        return self.page.locator(selector).inner_text(timeout=timeout or self.timeout)
    
    def _get_attribute(self, selector: str, attribute: str) -> str | None:
        """Get an attribute value from an element."""
        element = self.page.locator(selector).first
        if element.count() > 0:
            return element.get_attribute(attribute)
        return None
    
    def _get_all_elements(self, selector: str) -> list:
        """Get all matching elements."""
        return self.page.locator(selector).all()
    
    def _wait(self, milliseconds: int) -> None:
        """Wait for a specified time."""
        self.page.wait_for_timeout(milliseconds)
    
    def run(self, **kwargs) -> dict:
        """
        Main entry point - handles browser lifecycle and calls execute().
        
        This is what external code should call.
        """
        try:
            self._start_browser()
            return self.execute(**kwargs)
        except Exception as e:
            return {"error": str(e)}
        finally:
            self._stop_browser()
