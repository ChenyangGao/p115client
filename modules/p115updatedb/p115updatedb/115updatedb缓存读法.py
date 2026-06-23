
                    def readdir():
                        children = id_to_readdir.get(id)
                        if children:
                            children = dict(children)
                        payload.update({"custom_order": 1, "o": "user_utime", "asc": 0, "fc_mix": 1, "offset": 0})
                        done = False
                        if children:
                            can_merge = True
                            payload["limit"] = min(16, page_size)
                            mtime_groups: dict[int, set[int]] = {}
                            for cid, item in sorted(children.items(), key=lambda t: t[1]["mtime"], reverse=True):
                                try:
                                    mtime_groups[item["mtime"]].add(cid)
                                except KeyError:
                                    mtime_groups[item["mtime"]] = {cid}
                            n = len(children)
                            it = iter(mtime_groups.items())
                            his_mtime, his_ids = next(it)
                        else:
                            can_merge = False
                            payload["limit"] = page_size

                        class Break(Exception):
                            pass

                        def process(resp, /):
                            nonlocal can_merge, done, his_mtime, his_ids, n 
                            attr: AttrDict
                            for info in resp["data"]:
                                attr = normalize_attr2(info, ancestor)
                                if can_merge:
                                    cur_mtime = attr["mtime"]
                                    try:
                                        while his_mtime > cur_mtime:
                                            if children:
                                                for id in his_ids:
                                                    children.pop(id, None)
                                            n -= len(his_ids)
                                            if not n:
                                                can_merge = False
                                                raise Break
                                            his_mtime, his_ids = next(it)
                                        if his_mtime == cur_mtime:
                                            cur_id = attr["id"]
                                            if cur_id in his_ids:
                                                n -= 1
                                                if count - len(seen) == n:
                                                    yield Yield(attr)
                                                    for attr in cast(dict[int, AttrDict], children).values():
                                                        if attr["id"] not in seen:
                                                            yield Yield(attr)
                                                    done = True
                                                    return
                                                his_ids.remove(cur_id)
                                    except Break:
                                        pass
                                yield Yield(attr)


 