import dayjs from "dayjs";
import { FileInfo } from "/@/api";
import PlayIcon from "/@/assets/icon/play.svg?react";
import MoreIcon from "/@/assets/icon/more.svg?react";
import { Dropdown, MenuProps } from "antd";
import {
  InfoCircleOutlined,
  FileTextOutlined,
  DownloadOutlined,
  LinkOutlined,
} from "@ant-design/icons";
import { useState } from "react";
import PlayerList from "./PlayerList";

// prettier-ignore
// 定义文件类型与图标的对应关系
const fileIconMap: { [key: string]: string[] } = {
  image: ["jpg", "jpeg", "png", "gif", "webp", "bmp", "tiff", "svg", "heic", "raw", "psd"],
  pdf: ["pdf"],
  word: ["doc", "docx"],
  excel: ["xls", "xlsx"],
  powerpoint: ["ppt", "pptx"],
  text: ["txt", "ass", "srt"],
  code: ["js", "json", "html", "css", "scss", "py", "less", "md", "xml"],
  audio: ["mp3", "flac", "wav", "aac", "ogg", "wma", "alac", "aiff", "dsd", "pcm", "m4a", "opus", "amr", "ape", "au", "ra", "mp2", "ac3", "dts"],
  video: [
    "mkv", "mp4", "avi", "m2ts", "iso", "flv", "mov", "wmv", "webm", "mpeg", "mpg", "m4v", 
    "3gp", "3g2", "ts", "vob", "ogv", "mxf", "rm", "rmvb", "asf", "f4v", "f4p", "f4a", "f4b",
    "divx", "xvid", "swf", "ogm", "dvr-ms", "mts", "m2v", "gxf", "pvr", "mpeg1", "h264", 
    "h265", "yuv", "mjpeg", "bik", "bdmv", "mk3d", "m2p", "avs", "f4m"
  ],
  configuration: ["ini", "yaml", "yml"],
  db: ["db"],
  nfo: ["nfo"],
  ebook: ["epub", "mobi", "azw3", "kfx", "azw"],
  archive: ["zip", "rar", "tar", "7z"],
};

// 定义图标路径
const iconPathMap: { [key: string]: string } = {
  image: "/img/image.svg",
  pdf: "/img/pdf.svg",
  word: "/img/word.svg",
  excel: "/img/excel.svg",
  powerpoint: "/img/ppt.svg",
  text: "/img/text.svg",
  audio: "/img/audio.svg",
  video: "/img/video.svg",
  archive: "/img/archive.svg",
  code: "/img/code.svg",
  db: "/img/db.svg",
  nfo: "/img/nfo.svg",
  ebook: "/img/ebook.svg",
  configuration: "/img/config.svg",
  default: "/img/default.svg", // 默认图标路径
};

/**
 * 根据文件后缀名返回文件类型
 * @param fileName - 文件名
 * @returns 文件类型
 */
function getFileType(fileName: string): string {
  const fileExtension = fileName.split(".").pop()?.toLowerCase() || "";

  for (const [iconType, extensions] of Object.entries(fileIconMap)) {
    if (extensions.includes(fileExtension)) {
      return iconType;
    }
  }

  return "default";
}

/**
 * 根据文件后缀名返回图标路径
 * @param fileType - 文件名
 * @returns 文件类型
 */
function getFileIcon(fileType: string): string {
  return iconPathMap[fileType];
}

const FileItem = ({
  file,
  onClick,
}: {
  file: FileInfo;
  onClick: () => void;
}) => {
  const fileType = getFileType(file.name);
  const fileIcon = getFileIcon(fileType);

  const items: MenuProps["items"] = [
    file.is_directory
      ? null
      : {
          key: "download",
          label: "下载",
          icon: <DownloadOutlined style={{ fontSize: "16px" }} />,
          onClick: () => {
            window.location.href = `/api/download?pickcode=${file.pickcode}`;
          },
        },
    {
      key: "desc",
      label: "备注",
      icon: <InfoCircleOutlined style={{ fontSize: "16px" }} />,
      onClick: () => {
        window.open(`/api/desc?pickcode=${file.pickcode}`);
      },
    },
    {
      key: "attr",
      label: "属性",
      icon: <FileTextOutlined style={{ fontSize: "16px" }} />,
      onClick: () => {
        window.open(`/api/attr?pickcode=${file.pickcode}`);
      },
    },
    fileType === "video" || fileType === "audio"
      ? {
          key: "video",
          label: "M3U8",
          icon: <LinkOutlined style={{ fontSize: "16px" }} />,
          onClick: () => {
            window.open(`/api/m3u8?pickcode=${file.pickcode}`);
          },
        }
      : null,
  ].filter(Boolean);

  const [isModalOpen, setIsModalOpen] = useState(false);

  return (
    <tr
      className="file-item group cursor-pointer sm:hover:bg-[#FFFFFF0D] text-[14px] sm:group-hover:text-[15px] text-[#FFFFFFCC] sm:group-hover:text-[#ffffffee] transition-all duration-300 ease-in-out"
      onClick={onClick}
    >
      <td className="rounded-l-[8px]">
        <div className="flex items-center mb-[2px] px-0 sm:hover:px-[14px] py-[16px] transition-all duration-300 ease-in-out">
          {file.is_directory ? (
            <img
              src="/img/folder.svg"
              className="mr-2 w-[32px] h-[32px]"
              alt="folder"
            />
          ) : (
            <img src={fileIcon} className="mr-2 w-[32px] h-[32px]" alt="file" />
          )}
          {/* <div className="line-clamp-1">{file.name}</div> */}
          <div className="flex flex-col">
            <div className="line-clamp-1 break-all">{file.name}</div>
            <div className="block sm:hidden text-xs opacity-50">
              {dayjs(file.mtime * 1000).format("YYYY-MM-DD HH:mm")}
            </div>
          </div>
        </div>
      </td>
      <td className="hidden sm:table-cell whitespace-nowrap text-center min-w-[150px]">
        <div className="p-2">{file.format_size || "-"}</div>
      </td>
      <td className="hidden sm:table-cell whitespace-nowrap text-center min-w-[200px]">
        <div className="p-2">
          {dayjs(file.mtime * 1000).format("YYYY-MM-DD HH:mm")}
        </div>
      </td>
      <td className="whitespace-nowrap overflow-hidden rounded-r-[8px] text-center">
        <div className="flex gap-2 p-2 justify-end items-center">
          {fileType === "video" && (
            <div className="cursor-pointer ml-6 rounded-[6px] bg-[#FFFFFF0D] sm:hover:bg-[#ffffff] transition-all duration-300 ease-in-out">
              <div
                className="text-[14px] leading-[14px] text-[#ffffffcc] flex items-center px-[12px] py-[10px] sm:hover:text-[#000000] transition-all duration-300 ease-in-out"
                onClick={(e) => {
                  e.stopPropagation();
                  setIsModalOpen(true);
                }}
              >
                <PlayIcon className="w-[16px] h-[16px] mr-[4px]" />
                播放
              </div>
              <PlayerList
                file={file}
                isModalOpen={isModalOpen}
                setIsModalOpen={setIsModalOpen}
              />
            </div>
          )}
          <div
            className=" cursor-pointer rounded-[6px] bg-[#FFFFFF0D] hover:bg-[#ffffff] transition-all duration-300 ease-in-out"
            onClick={(e) => e.stopPropagation()}
          >
            <Dropdown menu={{ items }} trigger={["click"]}>
              <div className="text-[14px] leading-[14px] flex items-center px-[12px] py-[10px] hover:text-[#000000] transition-all duration-300 ease-in-out">
                <MoreIcon className="w-[16px] h-[16px]" />
              </div>
            </Dropdown>
          </div>
        </div>
      </td>
    </tr>
  );
};

export default FileItem;