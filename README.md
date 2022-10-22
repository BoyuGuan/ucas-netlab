# UCAS 计算机网络课程大作业

管博宇与吴义豪组队，选择课题五：写一个http服务器

# 10.17

sscanf()函数传参时要传地址，比如
```c
int a, b;
sscanf("%d-%d", &a, &b);
```
而sprintf()就要传实例，比如
```c
int a = 1, b = 2;
sprintf("%d-%d", a, b);
```
# 10.18
## 视频格式
最好使用AAC、H.264格式的视频，AAC、HEVC格式的视频传输可以，但解码速度不行。  
另外注意免费的阿里云学生服务器为1M的小水管，所以尽量选择480P及以下的视频，720P的场景变换少的视频（如口述类视频）是网速极限。
## 文件位置
注意`size_t`是`unsigned long`，大小离谱，表示文件大小的时候不用考虑溢出，输入输出要用 `%lu`。

# 10.19
## 解决pipe error
浏览器或者应用在不需要某个数据的时候（比如说拖拽进度条，拖拽前位置的数据就不再被需要）会直接关闭端口。此时再向对应该端口的描述符写就会出现 `pipe error`，此信号会导致进程崩溃，需要信号处理忽略这一信号。
## 解决分小块传输时的bug
注意在分小块传输时，对文件取地址时要加上 beign 

# 10.20
`SSL_read_ex`函数会一直等，不知为何。改成了用`SSL_read`函数

# 10.21
`SSL_read`函数与`read`，`SSL_write`函数与`write`基本行为相似，可以用类似的逻辑实现robust ssl io

# 10.22
长期连接时，有时候`rio_ssl_writen()`会报`SSL_ERROR_SSL`，出现错误。此时按照官网的要求不能使用`SSL_shutdown()`函数，目前先简单忽略了此错误，待进一步查看。