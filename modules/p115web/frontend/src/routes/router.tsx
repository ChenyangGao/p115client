import React from "react";
import Index from "/@/views/index";
import Player from "/@/views/player";

interface T {
  path: string;
  element: React.ReactNode;
  children?: Array<T>;
}

export const Router: Array<T> = [
  {
    path: "/",
    element: <Index />,
  },
  {
    path: "/player",
    element: <Player />,
  },
];
