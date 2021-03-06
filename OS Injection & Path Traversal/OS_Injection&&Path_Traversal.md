# OS Injection  

## Os Injection là gì ? 

-OS Command Injection (hay còn gọi là shell injection) là lỗ hổng cho phép kẻ tấn công thực thi các lệnh bất kì của hệ điều hành trên server chạy ứng dụng với đặc quyền của web server.  
-Nhiều trường hợp OS command injection là blind vulnerabilities. Có nghĩa là đầu ra sẽ không trả về trong response và ouput sẽ không hiển thị trên màn hình (hay còn gọi là 1 lỗ hổng tàng hình). Chúng ta có thể sử dụng 1 vài kỹ thuật để kiểm thử như sau: 
	+ Detecting blind OS command injection using time delays: Sử dụng time delays để xác định được blind vulnerabilities. Nó là độ trễ, cho phép chúng ta xác nhận rằng lệnh này đã được thực thi hay chưa dựa vào thời gian mà ứng dụng cần để đáp ứng. Điển hình là câu lệnh ping.
	+ Exploiting blind OS command injection by redirecting output: Có nghĩa là khai thác lỗ hổng OS Command Injection bằng cách chuyển hướng đầu ra.
	+Exploiting blind OS command injection using out-of-band (OAST) techniques: Sử dụng kỹ thuật OAST để khai thác Blind OS command. (Out-of-band Applicaiton Security Testing các bạn có thể gg nhé vì nó khá rộng và phức tạp nên mình sẽ không trình bày trong bài này)

### -Xảy ra ở đâu : 

-Lỗ hổng xảy ra khi một ứng dụng trên website có cung cấp chức năng cụ thể thực thi các câu lệnh hệ thống , cụ thể là gọi tới lệnh shell để thực thi một tác vụ với input do người dùng nhập vào mà không có cơ chế bảo vệ. 
-Trong quá trình phát triển ra 1 ứng dụng, chúng ta sẽ phải có những lúc phải dùng những OS Command Injection (tương tác file, đăng nhập truy xuất data, ...) vì chỉ có API hệ thống mới đáp ứng được yêu cầu như vậy. Đây cũng là điểm mấu chốt để chúng ta nhận ra có lỗi OS Command Injection hay không.

### -Nguyên nhân :  

-Các lỗ hổng OS Command Injection xảy ra khi phần mềm tích hợp dữ liệu trên ứng dụng do người dùng quản lý trong một lệnh, các dữ liệu này được thực thi. Nếu dữ liệu không được kiểm tra hoặc server không được bảo vệ thì hacker có thể sử dụng các siêu ký tự shell để thay đổi lệnh đang được thực thi để tấn công. 

### -Hacker có thể làm gì :  
-Lỗ hổng OS command injection có thể cho phép kẻ tấn công thực hiện các hành vi như: 
   +Thực thi lệnh hệ thống. 
	
   +Làm tổn hại tới ứng dụng, server chạy ứng dụng cũng như dữ liệu trên đó. 
	
   +Thực hiện SSRF: SSRF (Server Side Request Forgery) hay còn gọi là tấn công yêu cầu giả mạo từ phía máy chủ cho phép kẻ tấn công thay đổi tham số được sử dụng trên ứng 
dụng web để tạo hoặc kiểm soát các yêu cầu từ máy chủ dễ bị tấn công. 
	
   +Lấy được reverse shell: Reverse shell là 1 loại session shell (ngoài ra còn có web shell, bind shell,.. ) là shell có kết nối bắt nguồn từ 1 máy chủ đóng vai trò là target đến 1 máy chủ khác đóng vai trò host 
	
tuỳ theo đặc quyền của web server mà lỗ hổng này có thể cho phép kẻ tấn công thực hiện được các hành vi khác nhau. 

### -Ngăn chặn : 
#### + Giai đoạn phát triển :  

  ~Hạn chế sử dụng cách lệnh gọi hệ thống trong code ứng dụng nếu không thực sự cần thiết. 
	
  ~Chuẩn hóa dữ liệu đầu vào: 
	
  ~Tạo WhiteList : Giá trị nhập vào nằm trong whitelist các giá trị được sử dụng 
	
  ~Tạo format input đầu vào bằng kiểu dữ liệu. 
	
  ~Input chỉ chứa các ký tự chữ và số, không có cú pháp hoặc khoảng trắng nào khác. 
	
  ~Chỉ sử dụng API bảo mật để thực thi các lệnh như execFile(). Không giống như các API khác, nó chấp nhận một lệnh làm tham số đầu tiên và một mảng các đối số dòng lệnh làm tham số hàm thứ hai. Hiện tượng này đảm bảo rằng bản thân lệnh phải là một chương trình hợp lệ, không liên quan đến đầu vào nguy hiểm. 

#### - Giai đoạn thực tế

Set rules WAF kiểm tra lưu lượng truy cập cho các từ khóa hoặc ký tự đặc biệt. Nếu yêu cầu đến không có mẫu nào khớp với bất kỳ từ khóa hoặc ký tự đặc biệt nào bị từ chối, yêu cầu được cho phép. 

#### Ví dụ
-Ví dụ trong phần này mình sẽ sử dụng của DVWA (Damn Vulnerabilities Web Application) - một ứng dụng web phổ biến được dùng để học về các lỗ hổng bảo mật của ứng dụng web. 
-Ở đây, ứng dụng có một chức năng thực hiện lệnh ping với giá trị ip do người dùng nhập vào. 

 
```
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
	// Get input
	$target = $_REQUEST[ 'ip' ];

	// Determine OS and execute the ping command.
	if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
		// Windows
		$cmd = shell_exec( 'ping  ' . $target );
	}
	else {
		// *nix
		$cmd = shell_exec( 'ping  -c 4 ' . $target );
	}

	// Feedback for the end user
	$html .= "<pre>{$cmd}</pre>";
}

?>
 ```

 

# Path Traversal 

 

## Path Traversal là gì ? 

Path traversal( hay còn gọi là Directory traversal) là một lỗ hổng web cho phép kẻ tấn công đọc các file không mong muốn trên server. Nó dẫn đến việc bị lộ thông tin nhạy cảm của ứng dụng như thông tin đăng nhập , một số file hoặc thư mục của hệ điều hành. Trong một số trường hợp cũng có thể ghi vào các files trên server, cho phép kẻ tấn công có thể thay đổi dữ liệu hay thậm chí là chiếm quyền điều khiển server. 
 
-Về cơ bản thì 2 lỗ hồng này cùng xảy ra trong 1 ngữ cảnh tương tự nhau, tuy nhiên để phát hiện ra lỗi của Path Traversal thì lại dùng 1 cách khác.

Khi tiếp cận với một ứng dụng Web, việc kiểm tra nó có khả năng bị lỗi Path Traversal có thể được thực hiện bằng hai loại: 
	+ Nếu kẻ tấn công không thể có source thì chúng sẽ dùng spider để thực hiện kiểm tra Website và từ những kết quả mà spider mang lại chúng sẽ lần lượt kiểm tra các biến đối với các phương thức GET, POST hoặc COOKIE mà có khả năng bị lỗi. 
	+ Nếu kẻ tấn công có source code thì có thể tìm kiếm những hàm của những ngôn ngữ lập trình Web mà có khả năng gây ra lỗi Path Traversal.


## Ví dụ : 


-Một ví dụ đơn giản là việc lưu trữ ảnh trong hệ thống: 
  +Giả sử những file ảnh được dev lưu trong thư mục /var/www/html/blog/public/img/ 
	
  +Khi truy cập file avatar.jpg trên thư mực này dev có thể để link là GET photo/file?name=avatar.jpg. Lúc này webserver sẽ truy cập vào file ở đường dẫn /var/www/html/blog/public/img/avatar.jpg và trả về cho người dùng. 

  +Nhưng thay vì việc truyền file name là avatar.jpg hacker có thể truyền tên file là ../../../../../../etc/password. Lúc này webserver sẽ truy cập và trả về file ở đường dẫn /var/www/html/blog/public/img/../../../../../../etc/password. Đường dẫn này tương đương với /etc/pasword nên webserver sẽ trả về file hệ thống cho chúng ta. 
	
  +Tất nhiên trong thực tế tùy theo web server và config của chúng mà cách khai thác có thể khác, khó hơn chút và đa dạng hơn chút  


### Ngăn chặn:  

-Cách hiệu quả nhất để ngăn chặn các lỗ hổng Path Traversal là tránh chuyển đầu vào do người dùng cung cấp cho các API hệ thống tệp hoàn toàn. Nhiều chức năng ứng dụng làm điều này có thể được viết lại để cung cấp hành vi tương tự một cách an toàn hơn. 

-Nếu không thể tránh khỏi việc chuyển đầu vào do người dùng cung cấp cho API hệ thống tệp, thì hai lớp phòng thủ nên được sử dụng cùng nhau để ngăn chặn các cuộc tấn công: 

-Nên validate input của người dùng trước khi xử lý nó. 

-Sử dụng whitelist cho những giá trị được cho phép. 

-Hoặc tên file là những kí tự số,chữ không nên chứa những ký tự đặc biệt. 

 
Giải đoạn thực tế:  

WAF để lọc các mẫu yêu cầu HTTP nguy hiểm có thể chỉ ra các nỗ lực đi qua đường dẫn hoặc bao gồm tệp từ xa và cục bộ (RFI/LFI). 
 
