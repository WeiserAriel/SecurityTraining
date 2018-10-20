from selenium import webdriver
from selenium.webdriver.common.keys import Keys
import  time
def site_login(url , driver , username, password):
    driver.get (url)
    driver.find_element_by_id("txbLoginUserName").send_keys(username)
    driver.find_element_by_id("txbPassword").send_keys(password)
    driver.find_element_by_id("divSubmitLogin").click()
    time.sleep(10)
 main():
    website = 'https://www.goodi.co.il/Home/'
    driver = webdriver.Chrome(r"C:\Users\Ariel\PycharmProjects\Sandwicher\sandwicher\drivers\chromedriver_win32 \chromedriver.exe")
    driver.get(website)
    username = 'arielwe@mellanox.com'
    password = '0727eScYH'
    site_login(website, driver,username, password)

    get_phone_number(driver)



if __name__ == "__main__":
    main()
