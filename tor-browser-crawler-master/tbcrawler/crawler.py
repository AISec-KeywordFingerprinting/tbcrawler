import sys
from os.path import join, split
from pprint import pformat
from time import sleep, time

from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.common.by import By

import tbcrawler.common as cm
import tbcrawler.utils as ut
from tbcrawler.dumputils import Sniffer
from tbcrawler.log import wl_log


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
            self.controller.restart_tor()
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
        self.controller.restart_tor()
        for self.job.site in range(len(self.job.urls)):
            if len(self.job.url) > cm.MAX_FNAME_LENGTH:
                wl_log.warning("URL is too long: %s" % self.job.url)
                continue
            self._do_instance()
            sleep(float(self.job.config['pause_between_videos']))

    def _do_instance(self):
        for self.job.visit in range(self.job.visits):
            ut.create_dir(self.job.path)
            wl_log.info("*** 사이트를 방문 중입니다!! Visit #%s to %s ***", self.job.visit, self.job.url)
            # self.job.screen_num = 0
            with self.driver.launch():
                try:
                    self.driver.set_page_load_timeout(cm.SOFT_VISIT_TIMEOUT)
                except WebDriverException as seto_exc:
                    wl_log.error("Setting soft timeout %s", seto_exc)
            self.driver.tor_quit()

            self._do_restart()
            sleep(float(self.job.config['pause_between_loads']))
            self.post_visit()

    ##################################################################################
    # 만약 캡챠가 맞다면, Tor 경로 새롭게 설정 후 다시 방문하는 함수
    def _do_restart(self):
        if self._do_visit() is True:
            wl_log.warning("Crawler에서 토르 프로세스 재시작 중")
            self.controller.restart_tor()
            wl_log.warning("Crawler에서 토르 프로세스 재시작 완료")
            self._do_restart()

    ##################################################################################

    def _do_visit(self):
        with Sniffer(path=self.job.pcap_file, filter=cm.DEFAULT_FILTER,
                     device=self.device, dumpcap_log=self.job.pcap_log):
            sleep(1)  # make sure dumpcap is running

            isCaptcha = True
            if not isCaptcha:
                try:
                    screenshot_count = 0
                    with ut.timeout(cm.HARD_VISIT_TIMEOUT):
                        # begin loading page
<<<<<<< Updated upstream
                        self.driver.get(self.job.url)
                        sleep(1)  # sleep to catch some lingering AJAX-type traffic

=======
                        # self.driver.get(self.job.url)
                        # sleep(1)  # sleep to catch some lingering AJAX-type traffic
                        
                        ##################################################################################
                        # type keyword character by character
                        self.driver.get('http://www.google.com')
                        self.driver.implicitly_wait(1000)
                        sleep(3)
                    
                        try:
                            search = self.driver.find_element(By.NAME, 'q')
                            search_btn = self.driver.find_element(By.NAME, 'btnK')
                            
                            a = self.job.url
                            for c in list(a):
                                # 검색창에 키워드 입력 시 랜덤하게 발생하는 에러: Unknown exception: Message: Element <input class="gLFyf" name="q" type="text"> is not reachable by keyboard -> 이 에러가 발생하면 검색창에 키워드 입력이 안 됨, 스크린샷이 안 찍힘)
                                wl_log.warning("키워드 가져옴 %c", c)
                                WebDriverWait(self.driver,1).until(EC.presence_of_element_located((By.XPATH, "/html/body/div[1]/div[3]/form/div[1]/div[1]/div[1]/div/div[2]/input"))).send_keys(c)

                                #search.send_keys(c)
                                sleep(random.uniform(0.1, 0.7))
                            #search_btn.submit() # 검색 결과 안 넘어감(스크린샷은 검색창에 키워드 입력이 되어 있고, 아래 연관 검색어 있는 상태)
                            search.send_keys(Keys.RETURN) # 검색 결과 안 넘어감(스크린샷은 검색창에 키워드 입력만 된 상태)
                            #search_btn.click() # 에러 메세지-CAPTCHA!(스크린샷은 캡챠)
                            #WebDriverWait(self.driver,1).until(EC.presence_of_element_located((By.XPATH, "//*/form/div[1]/div[1]/div[1]/div/div[2]/input"))).send_keys(Keys.ENTER) # 검색 결과 안 넘어감(스크린샷은 검색창에 키워드 입력만 된 상태)
                            #WebDriverWait(self.driver,1).until(EC.element_to_be_clickable((By.XPATH, "/html/body/div[1]/div[3]/form/div[1]/div[1]/div[2]/div[2]/div[5]/center/input[1]"))).click() #0208 xpath 교체 # 에러 발생-element <input class="gNO89b" name="btnK" type="submit"> is not clickable at point (415,271) because another element <div class="pcTkSc"> obscures it ->  xpath 교체 완료 ->
                            sleep(1)
                            
                        except (ElementNotVisibleException, NoSuchElementException,TimeoutException):
                            wl_log.warning("try 실행 안됨")
                            result = "CAPTCHA"
                            print("Exception!!")
                        
                        ##################################################################################
>>>>>>> Stashed changes
                        # take first screenshot
                        if self.screenshots:
                            try:
                                self.driver.get_screenshot_as_file(self.job.png_file(screenshot_count))
                                screenshot_count += 1
                            except WebDriverException:
                                wl_log.error("Cannot get screenshot.")

                except (cm.HardTimeoutException, TimeoutException):
                    wl_log.error("Visit to %s reached hard timeout!", self.job.url)
                except Exception as exc:
                    wl_log.error("Unknown exception: %s", exc)
            else:
                isCaptcha = True
                wl_log.error("CAPTCHA!")
        return isCaptcha


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