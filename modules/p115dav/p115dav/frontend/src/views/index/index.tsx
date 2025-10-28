import { Ancestor, FileInfo, getAncestors, getList } from "/@/api";
import { useSearchParams } from "react-router-dom";
import FileItem from "./components/FileItem";
import useSWR from "swr";
import { Fragment } from "react";
import { message } from "antd";
import Spin from "/@/assets/icon/spin.svg?react";

const getData = async (id: number | string) => {
  const { ancestors, children } = await getList({ id });
  return { fileList: children, ancestors };
};

const Index = () => {
  let [searchParams, setSearchParams] = useSearchParams();

  const id = searchParams.get("id") || 0;

  const {
    data,
    error: fileListError,
    isLoading: isFileListLoading,
  } = useSWR<{ fileList: FileInfo[]; ancestors: Ancestor[] }>(
    ["/list", id],
    ([_url, id]: any) => getData(id)
  );

  const { fileList, ancestors } = data || {
    fileList: [],
    ancestors: [],
  };

  const navTo = (file: Pick<FileInfo, "id">) => {
    setSearchParams({ id: file.id });
  };

  const renderFileList = () => {
    if (isFileListLoading) {
      return (
        <div className="flex items-center text-[14px] text-[#ffffffa8] py-[12px]">
          <Spin className="animate-spin h-[22px] w-[22px] mr-[8px]  text-[#ffffff]" />
          <span className="leading-none">加载中...</span>
        </div>
      );
    }

    if (fileListError) {
      return <div>错误: {fileListError.message}</div>;
    }

    return (
      <table className="table-auto w-full" rules="none">
        <thead>
          <tr className="hidden sm:table-row text-[13px] text-[#ffffff4f]">
            <th className="text-left py-[4px] w-full">名称</th>
            <th className="text-center py-[4px] whitespace-nowrap">大小</th>
            <th className="text-center py-[4px] whitespace-nowrap">修改时间</th>
            <th className="text-right py-[4px] pr-[14px]">操作</th>
          </tr>
        </thead>
        <tbody>
          {fileList?.map((file) => {
            return (
              <FileItem
                key={file.pickcode}
                file={file}
                onClick={() => {
                  if (file.is_dir) {
                    navTo(file);
                  }
                }}
              />
            );
          })}
        </tbody>
      </table>
    );
  };

  return (
    <div>
      {/* 面包屑 */}
      <div className="flex flex-wrap items-center mb-[12px] text-[#FFFFFFaa] text-[14px]">
        <img
          src="/img/home.svg"
          className="mr-[6px] w-[16px] h-[16px] opacity-25"
          alt="back"
        />
        <div
          className="pr-[4px] hover:text-[#ffffffee] cursor-pointer  transition-all duration-300 ease-in-out whitespace-nowrap"
          onClick={() => {
            navTo({ id: 0 });
          }}
        >
          首页
        </div>
        {ancestors?.map((item, index) => {
          return (
            <Fragment key={ item.id }>
              <span
                className="hover:text-[#ffffffee] cursor-pointer  transition-all duration-300 ease-in-out"
                style={{ fontWeight: "bold" }}
                onClick={() => {
                  navTo({ id: item.id });
                }}
              >
                {item.name}
              </span>
              { index != ancestors.length - 1 && "/"}
            </Fragment>
          );
        })}
        <div className="group flex items-center justify-center rounded-[4px] ml-[12px] hover:bg-[#ffffff24] transition-all duration-300 ease-in-out">
          <img
            src="/img/copy.svg"
            className="cursor-pointer w-[28px] h-[28px] opacity-30 group-hover:opacity-80 transition-all duration-300 ease-in-out group-hover:filter"
            alt="复制路径"
            onClick={() => {
              navigator.clipboard.writeText(id).then(
                () => {
                  message.success("已复制路径：" + id);
                },
                () => {
                  message.error("复制路径失败，请手动复制");
                }
              );
            }}
          />
        </div>
      </div>
      <div className="z-10 sticky top-[--safe-area-inset-top] bg-[#131313]">
        {/* 返回上级目录 */}
        {id != 0 && (
          <div
            className="mb-[0px] text-[14px] text-[#FFFFFFCC] hover:text-[15px] hover:text-[#ffffffee] hover:px-[14px] py-[12px] rounded-[8px] cursor-pointer hover:bg-[#ffffff0d] transition-all duration-300 ease-in-out"
            onClick={async () => {
              const parent = ancestors[ancestors.length-1];
              setSearchParams({ id: parent.parent_id });
            }}
          >
            <div className="flex items-center">
              <img
                src="/img/back.svg"
                className="mr-[6px] w-[9px] opacity-25"
                alt="back"
              />
              返回上级目录
            </div>
          </div>
        )}
      </div>

      {/* 文件列表 */}
      {renderFileList()}
    </div>
  );
};

export default Index;
