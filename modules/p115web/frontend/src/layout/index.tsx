import { ConfigProvider } from "antd";
import React from "react";
import { Outlet } from "react-router-dom";
import Header from "/@/layout/components/header";
import zhCN from "antd/lib/locale/zh_CN";

const BasicLayout: React.FC = () => {
  return (
    <ConfigProvider locale={zhCN}>
      <div className="h-full flex flex-col">
        <Header />
        <div className="bg-[#131313] flex-1 mx-auto box-border px-[16px] py-[16px] container">
          <Outlet />
        </div>
      </div>
    </ConfigProvider>
  );
};

export default BasicLayout;
