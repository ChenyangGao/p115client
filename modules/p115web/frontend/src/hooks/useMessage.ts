import { useContext } from "react";
import { MessageContext } from "/@/routes";

export const useMessage = () => {
  const messageApi = useContext(MessageContext);
  const config = {
    style: {
      marginTop: "90px",
    }
  };
  const success = (content: string) => {
    return messageApi?.success({
      ...config,
      content,
    });
  };

  const warning = (content: string) => {
    return messageApi?.warning({
      ...config,
      content,
    });
  };

  const error = (content: string) => {
    return messageApi?.error({
      ...config,
      content,
    });
  };

  return {
    success,
    warning,
    error,
  };
};
