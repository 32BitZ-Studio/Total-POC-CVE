# CVE-2017-13286
CVE-2017-13286 Poc(can not use)

All resources are sourced from this article
https://bbs.kanxue.com/thread-268506.htm

- 引起这个漏洞的主要原因是parcel对象读写不一致，具体可以追溯到如下代码
```java
public void writeToParcel(Parcel dest, int flags) {
        if (dest == null) {
            throw new IllegalArgumentException("dest must not be null");
        }
        dest.writeInt(mRotation);
        dest.writeInt(mSurfaceGroupId);
        dest.writeInt(mSurfaceType);
        dest.writeInt(mConfiguredSize.getWidth());
        dest.writeInt(mConfiguredSize.getHeight());
        dest.writeInt(mIsDeferredConfig ? 1 : 0);
        dest.writeInt(mIsShared ? 1 : 0);
        dest.writeTypedList(mSurfaces);
}
 
private OutputConfiguration(@NonNull Parcel source) {
        int rotation = source.readInt();
        int surfaceSetId = source.readInt();
        int surfaceType = source.readInt();
        int width = source.readInt();
        int height = source.readInt();
        boolean isDeferred = source.readInt() == 1;
        // missing write mIsShared
        ArrayList<Surface> surfaces = new ArrayList<Surface>();
        source.readTypedList(surfaces, Surface.CREATOR);
 
        checkArgumentInRange(rotation, ROTATION_0, ROTATION_270, "Rotation constant");
        ...
        ...
        ...
}
```
- 可以看到在AOSP的这个版本里，mIsShared并未读取，却被写了
- 利用这个我们可以构造恶意的parcel序列化数据，让系统执行一些东西

- 漏洞代码在AOSP的目录为：frameworks/base/core/java/android/hardware/camera2/params/OutputConfiguration.java
- 这个不仅被修复了，现在的序列化对象添加了更多的默认元素
