import * as React from "react";
import { Routes, Route, Outlet } from "react-router-dom";
import Layout from "/@/layout";
import { ConfigProvider, Result, Spin, message } from "antd";
import { createContext } from "react";
import { Router } from "./router";
import zhCN from "antd/lib/locale/zh_CN";
import { MessageInstance } from "antd/es/message/interface";

export const MessageContext = createContext<MessageInstance | null>(null);

const Config = () => {
  const [messageApi, contextHolder] = message.useMessage();

  return (
    <ConfigProvider locale={zhCN}>
      <MessageContext.Provider value={messageApi}>
        {contextHolder}
        <Outlet />
      </MessageContext.Provider>
    </ConfigProvider>
  );
};

const BasicRoutes = () => {
  return (
    <React.Suspense fallback={<Spin />}>
      <Routes>
        <Route element={<Config />}>
          <Route path="/" element={<Layout />}>
            {Router?.map(({ element, path }) => (
              <Route key={path} path={path} element={element} />
            ))}
          </Route>
          <Route
            path="/403"
            element={
              <Result
                status="403"
                title="403"
                subTitle="对不起，您没有权限访问这个页面"
              />
            }
          />
          <Route
            path="/500"
            element={
              <Result status="500" title="500" subTitle="服务器开小差啦！" />
            }
          />
          <Route
            path="*"
            element={
              <Result
                status="404"
                title="404"
                subTitle="Sorry, the page you visited does not exist."
              />
            }
          />
        </Route>
      </Routes>
    </React.Suspense>
  );
};

export default BasicRoutes;
