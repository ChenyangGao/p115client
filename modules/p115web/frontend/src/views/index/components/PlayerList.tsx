import { Modal } from "antd";
import { FileInfo } from "/@/api";

const getPlayer = (file: FileInfo) => {
  const url = `${window.location.protocol}//${window.location.host}/api/download?pickcode=${file.pickcode}`;
  const suffix = file.name.split(".").pop();
  return [
    {
      name: "IINA",
      url: `iina://weblink?url=${url}`,
      icon: "/img/iina.svg",
    },
    {
      name: "Pot",
      url: `potplayer://${url}`,
      icon: "/img/potplayer.svg",
    },
    {
      name: "VLC",
      url: `vlc://${url}`,
      icon: "/img/vlc.svg",
    },
    {
      name: "Fileball",
      url: `filebox://play?url=${url}`,
      icon: "/img/fileball.svg",
    },
    {
      name: "MX",
      url: `intent:${url}#Intent;package=com.mxtech.videoplayer.pro;S.title=;end`,
      icon: "/img/mxplayer.svg",
    },
    {
      name: "Infuse",
      url: `infuse://x-callback-url/play?url=${url}`,
      icon: "/img/infuse.svg",
    },
    {
      name: "nPlayer",
      url: `nplayer-${url}`,
      icon: "/img/nplayer.svg",
    },
    // {
    //   name: "Omni",
    //   url: `omniplayer://weblink?url=${url}`,
    //   icon: "/img/omni.png",
    // },
    {
      name: "Fig",
      url: `figplayer://weblink?url=${url}`,
      icon: "/img/fig.png",
    },
    {
      name: "MPV",
      url: `mpv://${url}`,
      icon: "/img/mpv.png",
    },
    {
      name: "在线播放",
      url: `/player?pickcode=${file.pickcode}&real_type=${suffix}`,
      icon: "/img/artplayer.png",
    },
  ];
};

// 播放器跳转列表
const PlayerList = ({
  file,
  isModalOpen,
  setIsModalOpen,
}: {
  file: FileInfo;
  isModalOpen: boolean;
  setIsModalOpen: (isModalOpen: boolean) => void;
}) => {
  const handleOk = () => {
    setIsModalOpen(false);
  };

  const handleCancel = () => {
    setIsModalOpen(false);
  };

  return (
    <Modal
      open={isModalOpen}
      onOk={handleOk}
      onCancel={handleCancel}
      centered
      width="auto"
      footer={null}
    >
      {
        <div>
          <div className="text-center mb-8 text-[18px] text-[#ffffffcc] font-semibold">
            选择播放器
          </div>
          <div className="grid px-6 pb-6 grid-cols-5 gap-x-4 gap-y-4">
            {getPlayer(file).map((player) => (
              <div
                key={player.name}
                className="flex flex-col items-center justify-center space-y-[8px] w-[100px] h-[104px] rounded-[10px] hover:bg-[#ffffff0f] cursor-pointer transition-all duration-300 ease-in-out"
              >
                <a href={player.url}>
                  <img
                    src={player.icon}
                    className="w-[50px] h-[50px]"
                    alt="player"
                  />
                </a>
                <span className="text-[#FFFFFFCC] text-[14px]">
                  {player.name}
                </span>
              </div>
            ))}
          </div>
        </div>
      }
    </Modal>
  );
};

export default PlayerList;
