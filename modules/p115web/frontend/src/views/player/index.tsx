import { useEffect, useRef } from "react";
import Artplayer from "artplayer";
import { useSearchParams } from "react-router-dom";
import Hls from "hls.js";

const Player = () => {
  let [searchParams, _] = useSearchParams();

  const pickcode = searchParams.get("pickcode");
  const realType = searchParams.get("real_type");

  const artRef = useRef<HTMLDivElement>(null);
  const artInstanceRef = useRef<Artplayer | null>(null);

  const createArtOption = () => {
    const art = artInstanceRef.current!;
    const container = artRef.current!;

    const option: Artplayer["Option"] = {
      container: container,
      setting: true,
      fullscreen: true,
      fullscreenWeb: true,
      url: `/api/m3u8?pickcode=${pickcode}&definition=3`,
      type: "m3u8",
      settings: [
        {
          html: "画质",
          width: 150,
          selector: [
            {
              html: "转码 HD",
              url: `/api/m3u8?pickcode=${pickcode}&definition=3`,
              type: "m3u8",
            },
            {
              html: "转码 UD",
              url: `/api/m3u8?pickcode=${pickcode}&definition=4`,
              type: "m3u8",
            },
            {
              html: "直连 原始画质",
              url: `/api/download?pickcode=${pickcode}`,
              type: realType,
            },
          ],
          onSelect: function (item, $dom, event) {
            console.info(item, $dom, event);
            art.switchQuality(item.url);
            art.type = item.type;
            art.notice.show = "切换画质: " + item.html;
            return item.html;
          },
        },
      ],
      customType: {
        m3u8: function playM3u8(
          video: HTMLMediaElement,
          url: string,
          art: Artplayer
        ) {
          if (Hls.isSupported()) {
            if (art.hls) art.hls.destroy();
            const hls = new Hls();
            hls.loadSource(url);
            hls.attachMedia(video);
            art.hls = hls;
            art.on("destroy", () => hls.destroy());
          } else if (video.canPlayType("application/vnd.apple.mpegurl")) {
            video.src = url;
          } else {
            art.notice.show = "不支持播放格式: m3u8";
          }
        },
      },
    };

    return option;
  };

  const getInstance = (art: Artplayer) => console.info(art);

  useEffect(() => {
    if (!artRef.current) {
      return;
    }

    const art = new Artplayer(createArtOption());
    artInstanceRef.current = art;

    art.on("error", (error, reconnectTime) => {
      console.info(error, reconnectTime);
    });

    if (getInstance && typeof getInstance === "function") {
      getInstance(art);
    }

    return () => {
      if (art && art.destroy) {
        art.destroy(false);
      }
    };
  }, []);

  if (!pickcode) {
    return <div>无效的 pickcode</div>;
  }

  return (
    <div className="md:px-20 h-full flex justify-center items-center rounded-[50px]">
      <div
        className="w-full aspect-video rounded-[50px]"
        // 播放器的尺寸依赖于容器 container 的尺寸，所以你的容器 container 必须是有尺寸的
        // style={{
        //   width: "100%",
        //   height: "720px",
        //   margin: "0",
        // }}
        ref={artRef}
      />
    </div>
  );
};

export default Player;
