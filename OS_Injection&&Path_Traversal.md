# OS Injection  

## Os Injection là gì ? 

	-OS Command Injection (hay còn gọi là shell injection) là lỗ hổng cho phép kẻ tấn công thực thi các lệnh bất kì của hệ điều hành trên server chạy ứng dụng với đặc quyền của web server.  

### -Xảy ra ở đâu : 

	-Lỗ hổng xảy ra khi một ứng dụng trên website có cung cấp chức năng cụ thể thực thi các câu lệnh hệ thống , cụ thể là gọi tới lệnh shell để thực thi một tác vụ với input do người dùng nhập vào mà không có cơ chế bảo vệ. 

### -Nguyên nhân :  

-	Các lỗ hổng OS Command Injection xảy ra khi phần mềm tích hợp dữ liệu trên ứng dụng do người dùng quản lý trong một lệnh, các dữ liệu này được thực thi. Nếu dữ liệu không được kiểm tra hoặc server không được bảo vệ thì hacker có thể sử dụng các siêu ký tự shell để thay đổi lệnh đang được thực thi để tấn công. 

### -Hacker có thể làm gì :  
	-Lỗ hổng OS command injection có thể cho phép kẻ tấn công thực hiện các hành vi như: 
		+Thực thi lệnh hệ thống. 
		+Làm tổn hại tới ứng dụng, server chạy ứng dụng cũng như dữ liệu trên đó. 
		+Thực hiện SSRF. 
		+Lấy được reverse shell. 
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
 

### Ngăn chặn:  

Cách hiệu quả nhất để ngăn chặn các lỗ hổng Path Traversal là tránh chuyển đầu vào do người dùng cung cấp cho các API hệ thống tệp hoàn toàn. Nhiều chức năng ứng dụng làm điều này có thể được viết lại để cung cấp hành vi tương tự một cách an toàn hơn. 

Nếu không thể tránh khỏi việc chuyển đầu vào do người dùng cung cấp cho API hệ thống tệp, thì hai lớp phòng thủ nên được sử dụng cùng nhau để ngăn chặn các cuộc tấn công: 

Nên validate input của người dùng trước khi xử lý nó. 

Sử dụng whitelist cho những giá trị được cho phép. 

Hoặc tên file là những kí tự số,chữ không nên chứa những ký tự đặc biệt. 

 

 
