# UCAS 计算机网络课程大作业

管博宇与吴义豪组队，选择课题五：写一个http服务器

# 10.18两个坑
## 最好使用AAC、H.264格式的视频，AAC、HEVC格式的视频传输可以，但解码速度不行。
## 注意size_t是unsigned long，大小离谱，表示文件大小的时候不用考虑溢出，输入输出然后要用 %lu s