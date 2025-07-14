import { defHttp } from "/@/http";

export interface Ancestor {
  id: number;
  parent_id: number;
  name: string;
  is_directory: boolean;
}

export interface FileInfo {
  id: number;
  parent_id: number;
  name: string;
  path: string;
  pickcode: string;
  is_directory: boolean;
  sha1: string | null;
  size: number | null;
  format_size: string;
  ico: string;
  ctime: number;
  mtime: number;
  atime: number;
  thumb: string;
  star: boolean;
  labels: any[];
  score: number;
  hidden: boolean;
  described: boolean;
  ancestors: Ancestor[];
  url?: string;
  short_url?: string;
}

export type FileListResponse = FileInfo[];

/**
 * 获取文件或目录的属性
 * @param params.pickcode - 文件或目录的 pickcode，优先级高于 id
 * @param params.id - 文件或目录的 id，优先级高于 path
 * @param params.path - 文件或目录的路径，优先级高于 path2
 * @returns 返回文件或目录的属性信息
 */
export const getFileAttr = (params: {
  pickcode?: string;
  id?: number;
  path?: string;
}) =>
  defHttp.get({
    url: `/attr`,
    params,
  });

/**
 * 罗列对应目录的所有文件和目录属性
 * @param params.pickcode - 文件或目录的 pickcode，优先级高于 id
 * @param params.id - 文件或目录的 id，优先级高于 path
 * @param params.path - 文件或目录的路径，优先级高于 path2
 * @returns 返回目录下的所有文件和目录属性列表
 */
export const getList = (params: {
  pickcode?: string;
  id?: number;
  path?: string;
}) =>
  defHttp.get<FileListResponse>({
    url: `/list`,
    params,
  });

/**
 * 获取文件或目录的祖先节点列表（包含自己）
 * @param params.pickcode - 文件或目录的 pickcode，优先级高于 id
 * @param params.id - 文件或目录的 id，优先级高于 path
 * @param params.path - 文件或目录的路径，优先级高于 path2
 * @returns 返回祖先节点列表
 */
export const getAncestors = (params: {
  pickcode?: string;
  id?: number;
  path?: string;
}) =>
  defHttp.get<Ancestor[]>({
    url: `/ancestors`,
    params,
  });

/**
 * 获取文件或目录的备注
 * @param params.pickcode - 文件或目录的 pickcode，优先级高于 id
 * @param params.id - 文件或目录的 id，优先级高于 path
 * @param params.path - 文件或目录的路径，优先级高于 path2
 * @returns 返回文件或目录的备注信息
 */
export const getDesc = (params: {
  pickcode?: string;
  id?: number;
  path?: string;
}) =>
  defHttp.get({
    url: `/desc`,
    params,
  });

/**
 * 获取文件的下载链接
 * @param params.pickcode - 文件或目录的 pickcode，优先级高于 id
 * @param params.id - 文件或目录的 id，优先级高于 path
 * @param params.path - 文件或目录的路径，优先级高于 path2
 * @param params.web - 是否使用 web 接口获取下载链接，如果文件被封禁但小于 115 MB，启用此选项可成功下载文件
 * @returns 返回文件的下载链接
 */
export const getUrl = (params: {
  pickcode?: string;
  id?: number;
  path?: string;
  web?: boolean;
}) =>
  defHttp.get({
    url: `/url`,
    params,
  });

/**
 * 下载文件
 * @param params.pickcode - 文件或目录的 pickcode，优先级高于 id
 * @param params.id - 文件或目录的 id，优先级高于 path
 * @param params.path - 文件或目录的路径，优先级高于 path2
 * @param params.web - 是否使用 web 接口获取下载链接，如果文件被封禁但小于 115 MB，启用此选项可成功下载文件
 * @returns 返回下载的文件
 */
export const fileDownload = (params: {
  pickcode?: string;
  id?: number;
  path?: string;
  web?: boolean;
}) =>
  defHttp.get({
    url: `/download`,
    params,
  });

/**
 * 获取音视频的 m3u8 文件
 * @param params.pickcode - 文件或目录的 pickcode，优先级高于 id
 * @param params.id - 文件或目录的 id，优先级高于 path
 * @param params.path - 文件或目录的路径，优先级高于 path2
 * @param params.definition - 分辨率（3 - HD, 4 - UD）
 * @returns 返回音视频的 m3u8 文件
 */
export const fileM3u8 = (params: {
  pickcode?: string;
  id?: number;
  path?: string;
  definition?: number;
}) =>
  defHttp.get({
    url: `/m3u8`,
    params,
  });
