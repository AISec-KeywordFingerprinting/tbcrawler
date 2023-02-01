import sys
from os.path import join, split
from pprint import pformat
from time import sleep, time

from selenium.common.exceptions import TimeoutException, WebDriverException, ElementNotVisibleException, NoSuchElementException
from selenium.webdriver.common.by import By

import tbcrawler.common as cm
import tbcrawler.utils as ut
from tbcrawler.dumputils import Sniffer
from tbcrawler.log import wl_log

import random
from selenium.webdriver.common.keys import Keys

#added action chains for clicking element
from bs4 import BeautifulSoup
from selenium.webdriver.common.action_chains import ActionChains

class Crawler(object):
    def __init__(self, driver, controller, screenshots=True, device="eth0"):
        self.driver = driver
        self.controller = controller
        self.screenshots = screenshots
        self.device = device
        self.job = None

    def crawl(self, job):
        """Crawls a set of urls in batches."""
        self.job = job
        wl_log.info("Starting new crawl")
        wl_log.info(pformat(self.job))
        for self.job.batch in range(self.job.batches):
            wl_log.info("**** Starting batch %s ***" % self.job.batch)
            self._do_batch()
            sleep(float(self.job.config['pause_between_batches']))

    def post_visit(self):
        guard_ips = set([ip for ip in self.controller.get_all_guard_ips()])
        wl_log.debug("Found %s guards in the consensus.", len(guard_ips))
        wl_log.info("Filtering packets without a guard IP.")
        try:
            ut.filter_pcap(self.job.pcap_file, guard_ips)
        except Exception as e:
            wl_log.error("ERROR: filtering pcap file: %s.", e)
            wl_log.error("Check pcap: %s", self.job.pcap_file)

    def _do_batch(self):
        """
        Must init/restart the Tor process to have a different circuit.
        If the controller is configured to not pollute the profile, each
        restart forces to switch the entry guard.
        """
        with self.controller.launch():
            # (edit) number of urls -> number of keywords
            for self.job.site in range(len(self.job.urls)):
                if len(self.job.url) > cm.MAX_FNAME_LENGTH:
                    wl_log.warning("URL is too long: %s" % self.job.url)
                    continue
                self._do_instance()
                sleep(float(self.job.config['pause_between_videos']))

    def _do_instance(self):
        # (no edit needed) number of visits
        for self.job.visit in range(self.job.visits):
            ut.create_dir(self.job.path)
            wl_log.info("*** Visit #%s to %s ***", self.job.visit, self.job.url)
            #self.job.screen_num = 0
            with self.driver.launch():
                try:
                    self.driver.set_page_load_timeout(cm.SOFT_VISIT_TIMEOUT)
                except WebDriverException as seto_exc:
                    wl_log.error("Setting soft timeout %s", seto_exc)
                self._do_visit()
            sleep(float(self.job.config['pause_between_loads']))
            self.post_visit()

    def _do_visit(self):
        with Sniffer(path=self.job.pcap_file, filter=cm.DEFAULT_FILTER,
                     device=self.device, dumpcap_log=self.job.pcap_log):
            sleep(1)  # make sure dumpcap is running
            try:
                screenshot_count = 0
                with ut.timeout(cm.HARD_VISIT_TIMEOUT):
                    # begin loading page
                    #self.driver.get(self.job.url)
                    ###############################################################################
                    # type keyword character by character
                    page = self.driver.get('http://www.google.com')
                    self.driver.implicitly_wait(1)
                    #sleep(1)  # sleep to catch some lingering AJAX-type traffic
                    try:
                        search = self.driver.find_element(By.NAME, 'q')
                        search.click()
                        # (edit) self.page_url -> self.keyword?

                        a ='apple'
                        for c in list(a):
                            search.send_keys(c)
                            #time.sleep(random.uniform(0.1, 0.7))
                            self.driver.implicitly_wait(random.uniform(0.1, 0.7))
                        search.send_keys(Keys.RETURN)
                    except (ElementNotVisibleException, NoSuchElementException,TimeoutException):
                        result = "CAPTCHA"
                        print("Exception!!")
                    ###############################################################################
                    # take first screenshot
                    if self.screenshots:
                        try:
                            self.driver.get_screenshot_as_file(self.job.png_file(screenshot_count))
                            screenshot_count += 1
                        except WebDriverException:
                            wl_log.error("Cannot get screenshot.")

                    ###################################################################################################################
                    #check html file size
                    html_source = self.driver.page_source
                    html_source = html_source.encode('utf-8').decode('ascii', 'ignore')
                    soup = BeautifulSoup(html_source, "lxml")

                    with open(self.job.path + "htmlfile.txt", 'w') as f_html:
                        f_html.write(soup.prettify())
                    b = os.path.getsize(self.job.path + "htmlfile.txt")
                    print("out_png size->" + b)
                    if b<=10000: # smaller than 10kb
                        print("CAPTCHA!")
                    ###########################################################################################

            except (cm.HardTimeoutException, TimeoutException):
                wl_log.error("Visit to %s reached hard timeout!", self.job.url)
            except Exception as exc:
                wl_log.error("Unknown exception: %s", exc)


class CrawlJob(object):
    def __init__(self, config, urls):
        self.urls = urls
        self.visits = int(config['visits'])
        self.batches = int(config['batches'])
        self.config = config

        # state
        self.site = 0
        self.visit = 0
        self.batch = 0

    @property
    def pcap_file(self):
        return join(self.path, "capture.pcap")

    @property
    def pcap_log(self):
        return join(self.path, "dump.log")

    @property
    def instance(self):
        return self.batch * self.visits + self.visit

    @property
    def url(self):
        return self.urls[self.site]

    @property
    def path(self):
        attributes = [self.batch, self.site, self.instance]
        return join(cm.CRAWL_DIR, "_".join(map(str, attributes)))

    def png_file(self, time):
        return join(self.path, "screenshot_{}.png".format(time))

    def __repr__(self):
        return "Batches: %s, Sites: %s, Visits: %s" \
               % (self.batches, len(self.urls), self.visits)


