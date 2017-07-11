package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"crypto/sha256"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"

	"github.com/getlantern/systray"
	"github.com/getlantern/systray/example/icon"
	"github.com/inconshreveable/go-update"
	"github.com/klauspost/cpuid"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	gopnet "github.com/shirou/gopsutil/net"
	"github.com/skratchdot/open-golang/open"
)

func main() {
	// Should be called at the very beginning of main().
	systray.Run(onReady)
}

func hashSHA256(strToHash string) string {
	h := sha256.Sum256([]byte(strToHash))
	return "{SHA256}" + base64.StdEncoding.EncodeToString(h[:])
}

func doUpdate(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	err2 := update.Apply(resp.Body, update.Options{})
	if err2 != nil {
		// error handling
	}
	return err2
}

func onReady() {

	systray.SetIcon(icon.Data)
	systray.SetTitle("Awesome App")
	systray.SetTooltip("Lantern")
	mQuit := systray.AddMenuItem("Quit", "Quit the whole app")

	//machineHash := hashSHA256("abcd1234")

	//var params map[string]string
	//params["action"] = "checkIn"
	//params["machineHsh"] = machineHash
	//httpResult := httpPost("http://google.com", params)
	//println(httpResult)

	go func() {
		<-mQuit.ClickedCh
		systray.Quit()
		fmt.Println("Quit now...")
		os.Exit(1)
	}()

	// We can manipulate the systray in other goroutines
	go func() {
		systray.SetIcon(icon.Data)
		systray.SetTitle("Awesome App")
		systray.SetTooltip("Pretty awesome棒棒嗒")
		mChange := systray.AddMenuItem("Change Me", "Change Me")
		mChecked := systray.AddMenuItem("Unchecked", "Check Me")
		mEnabled := systray.AddMenuItem("Enabled", "Enabled")
		systray.AddMenuItem("Ignored", "Ignored")
		mURL := systray.AddMenuItem("Open Lantern.org", "my home")
		mQuit := systray.AddMenuItem("退出", "Quit the whole app")
		for {
			select {
			case <-mChange.ClickedCh:
				mChange.SetTitle("I've Changed")
			case <-mChecked.ClickedCh:
				if mChecked.Checked() {
					mChecked.Uncheck()
					mChecked.SetTitle("Unchecked")
				} else {
					mChecked.Check()
					mChecked.SetTitle("Checked")
				}
			case <-mEnabled.ClickedCh:
				mEnabled.SetTitle("Disabled")
				mEnabled.Disable()
			case <-mURL.ClickedCh:
				open.Run("https://www.getlantern.org")
			case <-mQuit.ClickedCh:
				systray.Quit()
				fmt.Println("Quit2 now...")
				return
			}
		}
	}()

	go func() {
		// get web server going
		mux := http.NewServeMux()
		mux.HandleFunc("/", SayName)
		mux.HandleFunc("/gethwdata", GetHardwareData)
		http.ListenAndServe(":8080", mux)
	}()

	go func() {
		for {
			v, _ := mem.VirtualMemory()
			// almost every return value is a struct
			fmt.Printf("Total: %v, Free:%v, UsedPercent:%f%%\n", v.Total, v.Free, v.UsedPercent)
			// convert to JSON. String() is also implemented
			// fmt.Println(v)
			runtimeOS := runtime.GOOS
			// cpu - get CPU number of cores and speed
			cpuStat, err := cpu.Info()
			dealwithErr(err)
			percentage, err := cpu.Percent(0, true)
			dealwithErr(err)
			// host or machine kernel, uptime, platform Info
			hostStat, err := host.Info()
			dealwithErr(err)

			println("CPU index number: " + strconv.FormatInt(int64(cpuStat[0].CPU), 10))
			println("VendorID: " + cpuStat[0].VendorID)
			println("Family: " + cpuStat[0].Family)
			println("Number of cores: " + strconv.FormatInt(int64(cpuStat[0].Cores), 10))
			println("Model Name: " + cpuStat[0].ModelName)
			println("Speed: " + strconv.FormatFloat(cpuStat[0].Mhz, 'f', 2, 64) + " MHz")

			for idx, cpupercent := range percentage {
				println("Current CPU utilization: [" + strconv.Itoa(idx) + "] " + strconv.FormatFloat(cpupercent, 'f', 2, 64) + "%")
			}

			println("Hostname: " + hostStat.Hostname)
			println("Uptime: " + strconv.FormatUint(hostStat.Uptime, 10))
			println("Number of processes running: " + strconv.FormatUint(hostStat.Procs, 10))

			// another way to get the operating system name
			// both darwin for Mac OSX, For Linux, can be ubuntu as platform
			// and linux for OS

			println("OS: " + hostStat.OS)
			println("Platform: " + hostStat.Platform)

			// the unique hardware id for this machine
			println("Host ID(uuid): " + hostStat.HostID)
			// other method
			fmt.Println("Name:", cpuid.CPU.BrandName)
			fmt.Println("PhysicalCores:", cpuid.CPU.PhysicalCores)
			fmt.Println("ThreadsPerCore:", cpuid.CPU.ThreadsPerCore)
			fmt.Println("LogicalCores:", cpuid.CPU.LogicalCores)
			fmt.Println("Family", cpuid.CPU.Family, "Model:", cpuid.CPU.Model)
			fmt.Println("Features:", cpuid.CPU.Features)
			fmt.Println("Cacheline bytes:", cpuid.CPU.CacheLine)
			fmt.Println("L1 Data Cache:", cpuid.CPU.Cache.L1D, "bytes")
			fmt.Println("L1 Instruction Cache:", cpuid.CPU.Cache.L1D, "bytes")
			fmt.Println("L2 Cache:", cpuid.CPU.Cache.L2, "bytes")
			fmt.Println("L3 Cache:", cpuid.CPU.Cache.L3, "bytes")
			fmt.Println("OS:", runtimeOS)

			interfaces, _ := net.Interfaces()
			for _, inter := range interfaces {
				var macAddress = inter.HardwareAddr.String()
				if macAddress != "" {
					println(macAddress)
				}
			}
			//println(strings.Join(string(interfaces), ""))
			println("-----------------------")
			interfaces2, _ := net.Interfaces()
			for _, inter := range interfaces2 {
				fmt.Println(inter.Name, inter.HardwareAddr)
				if addrs, err := inter.Addrs(); err == nil {
					for _, addr := range addrs {
						fmt.Println(inter.Name, "->", addr)
					}
				}
			}
			println("-----------------------")
			time.Sleep(1000 * time.Millisecond)
		}
	}()
}

func httpPost(targetURL string, params map[string]string) string {
	// Add form data
	v := url.Values{}
	for paramsKey, paramsVal := range params {
		v.Set(paramsKey, paramsVal)
	}
	/*v.Set("post_from", "client")
	v.Set("o", "omega")
	v.Set("b", "beta")
	v.Set("z", "zeta")
	v.Set("a", "alpha")
	v.Set("g", "gamma")
	v.Set("ch", "chip china cheap")
	v.Set("中", "中文 中国 中心")*/

	// Values.Encode() encodes the values into "URL encoded" form sorted by key.
	s := v.Encode()
	fmt.Printf("v.Encode(): %v\n", s)

	req, err := http.NewRequest("POST", targetURL, strings.NewReader(s))
	if err != nil {
		fmt.Printf("http.NewRequest() error: %v\n", err)
		return "err"
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	c := &http.Client{}
	resp, err := c.Do(req)
	if err != nil {
		fmt.Printf("http.Do() error: %v\n", err)
		return "err"
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("ioutil.ReadAll() error: %v\n", err)
		return "err"
	}

	return string(data)
}

func dealwithErr(err error) {
	if err != nil {
		fmt.Println(err)
		//os.Exit(-1)
	}
}

func GetHardwareData(w http.ResponseWriter, r *http.Request) {
	runtimeOS := runtime.GOOS
	// memory
	vmStat, err := mem.VirtualMemory()
	dealwithErr(err)

	// disk - start from "/" mount point for Linux
	// might have to change for Windows!!
	// don't have a Window to test this out, if detect OS == windows
	// then use "\" instead of "/"

	diskStat, err := disk.Usage("/")
	dealwithErr(err)

	// cpu - get CPU number of cores and speed
	cpuStat, err := cpu.Info()
	dealwithErr(err)
	percentage, err := cpu.Percent(0, true)
	dealwithErr(err)

	// host or machine kernel, uptime, platform Info
	hostStat, err := host.Info()
	dealwithErr(err)

	// get interfaces MAC/hardware address
	interfStat, err := gopnet.Interfaces()
	dealwithErr(err)

	html := "<html>OS : " + runtimeOS + "<br>"
	html = html + "Total memory: " + strconv.FormatUint(vmStat.Total, 10) + " bytes <br>"
	html = html + "Free memory: " + strconv.FormatUint(vmStat.Free, 10) + " bytes<br>"
	html = html + "Percentage used memory: " + strconv.FormatFloat(vmStat.UsedPercent, 'f', 2, 64) + "%<br>"

	// get disk serial number.... strange... not available from disk package at compile time
	// undefined: disk.GetDiskSerialNumber
	//serial := disk.GetDiskSerialNumber("/dev/sda")

	//html = html + "Disk serial number: " + serial + "<br>"

	html = html + "Total disk space: " + strconv.FormatUint(diskStat.Total, 10) + " bytes <br>"
	html = html + "Used disk space: " + strconv.FormatUint(diskStat.Used, 10) + " bytes<br>"
	html = html + "Free disk space: " + strconv.FormatUint(diskStat.Free, 10) + " bytes<br>"
	html = html + "Percentage disk space usage: " + strconv.FormatFloat(diskStat.UsedPercent, 'f', 2, 64) + "%<br>"

	// since my machine has one CPU, I'll use the 0 index
	// if your machine has more than 1 CPU, use the correct index
	// to get the proper data
	html = html + "CPU index number: " + strconv.FormatInt(int64(cpuStat[0].CPU), 10) + "<br>"
	html = html + "VendorID: " + cpuStat[0].VendorID + "<br>"
	html = html + "Family: " + cpuStat[0].Family + "<br>"
	html = html + "Number of cores: " + strconv.FormatInt(int64(cpuStat[0].Cores), 10) + "<br>"
	html = html + "Model Name: " + cpuStat[0].ModelName + "<br>"
	html = html + "Speed: " + strconv.FormatFloat(cpuStat[0].Mhz, 'f', 2, 64) + " MHz <br>"

	for idx, cpupercent := range percentage {
		html = html + "Current CPU utilization: [" + strconv.Itoa(idx) + "] " + strconv.FormatFloat(cpupercent, 'f', 2, 64) + "%<br>"
	}

	html = html + "Hostname: " + hostStat.Hostname + "<br>"
	html = html + "Uptime: " + strconv.FormatUint(hostStat.Uptime, 10) + "<br>"
	html = html + "Number of processes running: " + strconv.FormatUint(hostStat.Procs, 10) + "<br>"

	// another way to get the operating system name
	// both darwin for Mac OSX, For Linux, can be ubuntu as platform
	// and linux for OS

	html = html + "OS: " + hostStat.OS + "<br>"
	html = html + "Platform: " + hostStat.Platform + "<br>"

	// the unique hardware id for this machine
	html = html + "Host ID(uuid): " + hostStat.HostID + "<br>"

	for _, interf := range interfStat {
		html = html + "------------------------------------------------------<br>"
		html = html + "Interface Name: " + interf.Name + "<br>"

		if interf.HardwareAddr != "" {
			html = html + "Hardware(MAC) Address: " + interf.HardwareAddr + "<br>"
		}

		for _, flag := range interf.Flags {
			html = html + "Interface behavior or flags: " + flag + "<br>"
		}

		for _, addr := range interf.Addrs {
			html = html + "IPv6 or IPv4 addresses: " + addr.String() + "<br>"

		}

	}

	html = html + "</html>"

	w.Write([]byte(html))

}

func SayName(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello, I'm a machine and my name is [whatever]"))
}

func GCMEncrypter(text2crypt string, userKey string) {
	// The key argument should be the AES key, either 16 or 32 bytes
	// to select AES-128 or AES-256.
	key := []byte(userKey)
	plaintext := []byte(text2crypt)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	fmt.Printf("%x\n", ciphertext)
}

func GCMDecrypter(cipherText string, userKey string) {
	// The key argument should be the AES key, either 16 or 32 bytes
	// to select AES-128 or AES-256.
	key := []byte(userKey)
	ciphertext, _ := hex.DecodeString(cipherText)

	nonce, _ := hex.DecodeString("37b8e8a308c354048d245f6d")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("%s\n", plaintext)
	// Output: exampleplaintext
}
