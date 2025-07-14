// 定义一个hook来检测是否为移动设备
import { useEffect, useState } from "react";

// 定义移动设备的正则表达式，用来检测用户代理字符串
const mobileDeviceRegex =
  /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i;

// 使用React Hook来创建这个功能
export const useIsMobile = (): boolean => {
  const [isMobile, setIsMobile] = useState(false);

  useEffect(() => {
    // 检查用户代理字符串
    const userAgent =
      typeof window.navigator === "undefined" ? "" : navigator.userAgent;
    // 设置状态为true如果是移动设备
    setIsMobile(mobileDeviceRegex.test(userAgent));
  }, []);

  return isMobile;
};
