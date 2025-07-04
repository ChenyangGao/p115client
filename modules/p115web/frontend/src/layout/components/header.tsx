const Header: React.FC = () => {
  return (
    <div className="sm:mx-auto sm:container flex gap-2 items-center px-[16px] pb-[16px] sm:bg-inherit bg-[#212121] justify-center sm:justify-start">
      <img src="/img/logo.svg" alt="logo" className="w-[32px] h-[32px]" />
      <div
        className="text-[18px] text-[#ffffffaa]"
        style={{ fontFamily: "Poppins, sans-serif", fontWeight: 900 }}
      >
        115 FileLister
      </div>
    </div>
  );
};

export default Header;
