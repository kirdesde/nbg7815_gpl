#/bin/sh
# Generate photo,music,video folder.

for mount_partition in $(df |grep "/tmp/storage/usb" |awk '{print $6}');
do
	photo_path="$mount_partition/photo"
	music_path="$mount_partition/music"
	video_path="$mount_partition/video"
	[ ! -d $photo_path ] && mkdir -p $photo_path
	[ ! -d $music_path ] && mkdir -p $music_path
	[ ! -d $video_path ] && mkdir -p $video_path
	chmod 777 $photo_path
	chmod 777 $music_path
	chmod 777 $video_path
done

